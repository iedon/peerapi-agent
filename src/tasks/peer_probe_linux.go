//go:build linux

package tasks

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"net"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"github.com/iedon/peerapi-agent/session"
	"golang.org/x/sys/unix"
)

var (
	peerProbeAEAD    cipher.AEAD
	peerProbeRunning atomic.Bool
)

// initialize initializes the peer probe task (Linux-specific)
func (t *PeerProbeTask) initialize() error {
	keyData := strings.TrimSpace(t.cfg.PeerProbe.ProbePacketEncryptionKey)
	if keyData == "" {
		return fmt.Errorf("peerProbe.probePacketEncryptionKey is required when peer probe task is enabled")
	}

	key, err := deriveAES256Key(keyData)
	if err != nil {
		return fmt.Errorf("failed to derive peer probe encryption key: %w", err)
	}

	blk, err := aes.NewCipher(key)
	if err != nil {
		return fmt.Errorf("failed to create AES cipher: %w", err)
	}
	aead, err := cipher.NewGCM(blk)
	if err != nil {
		return fmt.Errorf("failed to initialize AES-GCM: %w", err)
	}
	peerProbeAEAD = aead

	if t.cfg.PeerAPI.ProbeServerPort <= 0 || t.cfg.PeerAPI.ProbeServerPort > math.MaxUint16 {
		return fmt.Errorf("peerApiCenter.probeServerPort must be between 1 and 65535")
	}

	t.logger.Info("Peer probe encryption initialized successfully")
	return nil
}

// executeProbes executes probe packets for the given sessions (Linux-specific)
func (t *PeerProbeTask) executeProbes(ctx context.Context, sessions []*session.Session) {
	if !peerProbeRunning.CompareAndSwap(false, true) {
		t.logger.Warn("Previous probe run still in progress, skipping this interval")
		return
	}
	defer peerProbeRunning.Store(false)

	endpoints, err := t.buildPeerProbeEndpoints()
	if err != nil {
		t.logger.Error("Endpoint configuration error: %v", err)
		return
	}

	packetBuilder := t.newProbePacketBuilder(endpoints)

	start := time.Now()
	workerCount := min(len(sessions), t.cfg.PeerProbe.SessionWorkerCount)
	if workerCount == 0 {
		workerCount = min(len(sessions), 8)
	}

	jobs := make(chan *session.Session, len(sessions))
	results := make(chan bool, len(sessions))

	var wg sync.WaitGroup
	for range workerCount {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for sess := range jobs {
				if ctx.Err() != nil {
					results <- false
					continue
				}
				packet, err := packetBuilder(sess)
				if err != nil {
					t.logger.Debug("Session %s packet build failed: %v", sess.UUID, err)
					results <- false
					continue
				}
				if err := t.probeSession(ctx, sess, endpoints, packet); err != nil {
					results <- false
				} else {
					results <- true
				}
			}
		}()
	}

	for _, sess := range sessions {
		jobs <- sess
	}
	close(jobs)

	go func() {
		wg.Wait()
		close(results)
	}()

	success := 0
	for r := range results {
		if r {
			success++
		}
	}

	t.logger.Info("Probed %d succeeded of %d enabled sessions using %d workers in %v",
		success, len(sessions), workerCount, time.Since(start))
}

// peerProbeEndpoints holds the source and destination addresses for probing
type peerProbeEndpoints struct {
	srcIPv4    net.IP
	srcIPv6    net.IP
	serverIPv4 net.IP
	serverIPv6 net.IP
	port       int
}

// buildPeerProbeEndpoints builds the probe endpoint configuration
func (t *PeerProbeTask) buildPeerProbeEndpoints() (peerProbeEndpoints, error) {
	var ep peerProbeEndpoints
	ep.port = t.cfg.PeerAPI.ProbeServerPort

	if t.cfg.IP.IPv4 != "" {
		ip := net.ParseIP(t.cfg.IP.IPv4)
		if ip == nil || ip.To4() == nil {
			return ep, fmt.Errorf("invalid peerProbe.srcIpv4: %s", t.cfg.IP.IPv4)
		}
		ep.srcIPv4 = ip.To4()
	}
	if t.cfg.IP.IPv6 != "" {
		ip := net.ParseIP(t.cfg.IP.IPv6)
		if ip == nil || ip.To16() == nil {
			return ep, fmt.Errorf("invalid peerProbe.srcIpv6: %s", t.cfg.IP.IPv6)
		}
		ep.srcIPv6 = ip.To16()
	}

	if t.cfg.PeerAPI.ProbeServerIPv4 != "" {
		ip := net.ParseIP(t.cfg.PeerAPI.ProbeServerIPv4)
		if ip == nil || ip.To4() == nil {
			return ep, fmt.Errorf("invalid peerApiCenter.probeServerIPv4: %s", t.cfg.PeerAPI.ProbeServerIPv4)
		}
		ep.serverIPv4 = ip.To4()
	}
	if t.cfg.PeerAPI.ProbeServerIPv6 != "" {
		ip := net.ParseIP(t.cfg.PeerAPI.ProbeServerIPv6)
		if ip == nil || ip.To16() == nil {
			return ep, fmt.Errorf("invalid peerApiCenter.probeServerIPv6: %s", t.cfg.PeerAPI.ProbeServerIPv6)
		}
		ep.serverIPv6 = ip.To16()
	}

	if ep.serverIPv4 == nil && ep.serverIPv6 == nil {
		return ep, errors.New("at least one probe server IP must be configured")
	}

	return ep, nil
}

// probeSession sends probe packets for a single session
func (t *PeerProbeTask) probeSession(ctx context.Context, sess *session.Session, ep peerProbeEndpoints, packet []byte) error {
	needsV4, needsV6 := t.determineProbeFamilies(sess)
	if !needsV4 && !needsV6 {
		return nil
	}

	var combined error
	if needsV4 {
		switch {
		case ep.srcIPv4 == nil:
			combined = errors.Join(combined, errors.New("IPv4 probe requested but srcIpv4 is not configured"))
		case ep.serverIPv4 == nil:
			combined = errors.Join(combined, errors.New("IPv4 probe requested but probeServerIPv4 is not configured"))
		default:
			err := t.dispatchProbes(ctx, ep.srcIPv4, ep.serverIPv4, ep.port, sess.Interface, packet)
			combined = errors.Join(combined, err)
		}
	}

	if needsV6 {
		switch {
		case ep.srcIPv6 == nil:
			combined = errors.Join(combined, errors.New("IPv6 probe requested but srcIpv6 is not configured"))
		case ep.serverIPv6 == nil:
			combined = errors.Join(combined, errors.New("IPv6 probe requested but probeServerIPv6 is not configured"))
		default:
			err := t.dispatchProbes(ctx, ep.srcIPv6, ep.serverIPv6, ep.port, sess.Interface, packet)
			combined = errors.Join(combined, err)
		}
	}

	return combined
}

// determineProbeFamilies determines which IP families to probe for a session
func (t *PeerProbeTask) determineProbeFamilies(sess *session.Session) (bool, bool) {
	mpbgp := slices.Contains(sess.Extensions, "mp-bgp")
	hasIPv4 := sess.IPv4 != "" || mpbgp
	hasIPv6 := sess.IPv6 != "" || sess.IPv6LinkLocal != "" || mpbgp
	return hasIPv4, hasIPv6
}

// probePacketBuilder is a function that builds a probe packet for a session
type probePacketBuilder func(sess *session.Session) ([]byte, error)

// newProbePacketBuilder creates a probe packet builder function
func (t *PeerProbeTask) newProbePacketBuilder(ep peerProbeEndpoints) probePacketBuilder {
	bannerBytes := append([]byte(t.cfg.PeerProbe.ProbePacketBanner), 0)
	ipv4LE := encodeIPv4LittleEndian(ep.srcIPv4)
	ipv6LE := encodeIPv6LittleEndian(ep.srcIPv6)

	return func(sess *session.Session) ([]byte, error) {
		if peerProbeAEAD == nil {
			return nil, errors.New("peer probe encryption key is not initialized")
		}

		payload := &bytes.Buffer{}
		timestamp := uint64(time.Now().UTC().Unix())
		if err := binary.Write(payload, binary.LittleEndian, timestamp); err != nil {
			return nil, fmt.Errorf("write timestamp: %w", err)
		}
		payload.WriteString(t.cfg.PeerAPI.RouterUUID)
		payload.WriteByte(0)
		payload.WriteString(sess.UUID)
		payload.WriteByte(0)
		if sess.ASN > math.MaxUint32 {
			return nil, fmt.Errorf("session %s ASN %d exceeds uint32", sess.UUID, sess.ASN)
		}
		var asnField [4]byte
		binary.LittleEndian.PutUint32(asnField[:], uint32(sess.ASN))
		payload.Write(asnField[:])
		payload.Write(ipv4LE[:])
		payload.Write(ipv6LE[:])

		nonceSize := peerProbeAEAD.NonceSize()
		nonce := make([]byte, nonceSize)
		if _, err := rand.Read(nonce); err != nil {
			return nil, fmt.Errorf("generate nonce: %w", err)
		}

		encrypted := peerProbeAEAD.Seal(nil, nonce, payload.Bytes(), nil)

		// Construct final packet
		totalLen := 3 + 2 + len(bannerBytes) + 4 + nonceSize + len(encrypted) + 2
		if totalLen > math.MaxUint16 {
			return nil, fmt.Errorf("probe packet too large (%d bytes)", totalLen)
		}

		buf := bytes.NewBuffer(make([]byte, 0, totalLen))
		buf.Write([]byte{0x42, 0x42, 0x42})
		var lenField [2]byte
		binary.LittleEndian.PutUint16(lenField[:], uint16(totalLen))
		buf.Write(lenField[:])
		buf.Write(bannerBytes)
		var nonceSizeField [4]byte
		binary.LittleEndian.PutUint32(nonceSizeField[:], uint32(nonceSize))
		buf.Write(nonceSizeField[:])
		buf.Write(nonce)
		buf.Write(encrypted)
		buf.Write([]byte{0x21, 0x89})
		return buf.Bytes(), nil
	}
}

// encodeIPv4LittleEndian encodes an IPv4 address in little-endian format
func encodeIPv4LittleEndian(ip net.IP) [4]byte {
	var out [4]byte
	if ip == nil {
		return out
	}
	ip4 := ip.To4()
	if ip4 == nil {
		return out
	}
	val := binary.BigEndian.Uint32(ip4)
	binary.LittleEndian.PutUint32(out[:], val)
	return out
}

// encodeIPv6LittleEndian encodes an IPv6 address in little-endian format
func encodeIPv6LittleEndian(ip net.IP) [16]byte {
	var out [16]byte
	if ip == nil {
		return out
	}
	ip16 := ip.To16()
	if ip16 == nil {
		return out
	}
	for i := 0; i < 16; i++ {
		out[i] = ip16[15-i]
	}
	return out
}

// dispatchProbes sends multiple probe packets with delay
func (t *PeerProbeTask) dispatchProbes(ctx context.Context, srcIP, dstIP net.IP, port int, iface string, packet []byte) error {
	if iface == "" {
		return errors.New("session interface is required for probe")
	}

	delay := time.Duration(t.cfg.PeerProbe.ProbePacketIntervalMs) * time.Millisecond
	if delay <= 0 {
		delay = 100 * time.Millisecond
	}

	var combined error
	for i := 0; i < t.cfg.PeerProbe.ProbePacketCount; i++ {
		if err := t.sendSingleProbe(ctx, dstIP, port, srcIP, iface, packet); err != nil {
			combined = errors.Join(combined, err)
		}
		if i+1 < t.cfg.PeerProbe.ProbePacketCount {
			timer := time.NewTimer(delay)
			select {
			case <-ctx.Done():
				timer.Stop()
				return errors.Join(combined, ctx.Err())
			case <-timer.C:
			}
		}
	}

	return combined
}

// sendSingleProbe sends a single probe packet
func (t *PeerProbeTask) sendSingleProbe(ctx context.Context, dstIP net.IP, dstPort int, srcIP net.IP, iface string, payload []byte) error {
	if dstIP == nil {
		return errors.New("destination IP missing")
	}
	if iface == "" {
		return errors.New("session interface is required for probe")
	}

	network := "udp6"
	if dstIP.To4() != nil {
		network = "udp4"
	}

	dialer := &net.Dialer{Timeout: 5 * time.Second}
	if srcIP != nil {
		addr := &net.UDPAddr{IP: srcIP}
		if srcIP.To4() == nil && srcIP.IsLinkLocalUnicast() {
			addr.Zone = iface
		}
		dialer.LocalAddr = addr
	}

	dialer.Control = func(network, address string, c syscall.RawConn) error {
		var controlErr error
		err := c.Control(func(fd uintptr) {
			if err := bindToInterface(fd, iface); err != nil {
				controlErr = err
				return
			}
			if network == "udp6" && srcIP != nil {
				if err := bindIPv6Src(fd, iface, srcIP); err != nil {
					controlErr = err
					return
				}
			}
		})
		if err != nil {
			return err
		}
		return controlErr
	}

	target := net.JoinHostPort(dstIP.String(), fmt.Sprintf("%d", dstPort))
	sendCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	conn, err := dialer.DialContext(sendCtx, network, target)
	if err != nil {
		return err
	}
	defer conn.Close()

	if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return err
	}

	_, err = conn.Write(payload)
	return err
}

// bindToInterface binds a socket to a specific network interface
func bindToInterface(fd uintptr, iface string) error {
	if iface == "" {
		return nil
	}
	return unix.SetsockoptString(int(fd), unix.SOL_SOCKET, unix.SO_BINDTODEVICE, iface)
}

// bindIPv6Src binds an IPv6 socket to a specific source address
func bindIPv6Src(fd uintptr, iface string, src net.IP) error {
	if src == nil || iface == "" {
		return nil
	}
	ifi, err := net.InterfaceByName(iface)
	if err != nil {
		return err
	}
	var pkt unix.Inet6Pktinfo
	copy(pkt.Addr[:], src.To16())
	pkt.Ifindex = uint32(ifi.Index)
	return setIPv6PktInfo(fd, &pkt)
}

// setIPv6PktInfo sets IPv6 packet info on a socket
func setIPv6PktInfo(fd uintptr, pkt *unix.Inet6Pktinfo) error {
	if pkt == nil {
		return nil
	}
	_, _, errno := unix.Syscall6(
		unix.SYS_SETSOCKOPT,
		fd,
		uintptr(unix.IPPROTO_IPV6),
		uintptr(unix.IPV6_PKTINFO),
		uintptr(unsafe.Pointer(pkt)),
		unsafe.Sizeof(*pkt),
		0,
	)
	if errno != 0 {
		return errno
	}
	return nil
}

// deriveAES256Key derives a 32-byte AES key from the input string
func deriveAES256Key(input string) ([]byte, error) {
	trimmed := strings.TrimSpace(input)
	if trimmed == "" {
		return nil, errors.New("empty encryption key")
	}

	// Try base64 decoding
	if key, err := decodeBase64Key(trimmed, base64.StdEncoding); err == nil && len(key) == 32 {
		return key, nil
	}
	if key, err := decodeBase64Key(trimmed, base64.StdEncoding.WithPadding(base64.NoPadding)); err == nil && len(key) == 32 {
		return key, nil
	}

	// Try hex decoding
	if decoded, err := hex.DecodeString(strings.TrimPrefix(trimmed, "0x")); err == nil && len(decoded) == 32 {
		key := make([]byte, 32)
		copy(key, decoded)
		return key, nil
	}

	// If exactly 32 bytes, use as-is
	if len(trimmed) == 32 {
		key := make([]byte, 32)
		copy(key, []byte(trimmed))
		return key, nil
	}

	// Otherwise, hash with SHA256
	sum := sha256.Sum256([]byte(trimmed))
	key := make([]byte, 32)
	copy(key, sum[:])
	return key, nil
}

// decodeBase64Key decodes a base64 key
func decodeBase64Key(input string, enc *base64.Encoding) ([]byte, error) {
	data, err := enc.DecodeString(input)
	if err != nil {
		return nil, err
	}
	return data, nil
}
