//go:build linux

package main

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
	"log"
	"math"
	"net"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

var (
	peerProbeAEAD    cipher.AEAD
	peerProbeRunning atomic.Bool
)

func initPeerProbe() error {
	keyData := strings.TrimSpace(cfg.PeerProbe.ProbePacketEncryptionKey)
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

	if cfg.PeerAPI.ProbeServerPort <= 0 || cfg.PeerAPI.ProbeServerPort > math.MaxUint16 {
		return fmt.Errorf("peerApiCenter.probeServerPort must be between 1 and 65535")
	}

	return nil
}

// peerProbeTask periodically probes active sessions.
func peerProbeTask(ctx context.Context, wg *sync.WaitGroup) {
	defer wg.Done()

	if !cfg.PeerProbe.Enabled {
		log.Println("[PeerProbe] Task disabled via configuration, skipping start")
		return
	}

	if err := initPeerProbe(); err != nil {
		log.Fatalf("[PeerProbe] Failed to initialize peer probe task: %v", err)
		return
	}

	interval := time.Duration(cfg.PeerProbe.IntervalSeconds) * time.Second
	if interval <= 0 {
		interval = 5 * time.Minute
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	runPeerProbe(ctx)

	for {
		select {
		case <-ctx.Done():
			log.Println("[PeerProbe] Shutting down peer probe task...")
			return
		case <-ticker.C:
			runPeerProbe(ctx)
		}
	}
}

func runPeerProbe(ctx context.Context) {
	if !cfg.PeerProbe.Enabled {
		return
	}
	if !peerProbeRunning.CompareAndSwap(false, true) {
		log.Println("[PeerProbe] Previous run still in progress, skipping this interval")
		return
	}
	defer finalizePeerProbeRun(ctx)
	defer peerProbeRunning.Store(false)

	sessions := collectProbeCandidateSessions()
	if len(sessions) == 0 {
		log.Println("[PeerProbe] No active sessions eligible for probing")
		return
	}

	endpoints, err := buildPeerProbeEndpoints()
	if err != nil {
		log.Printf("[PeerProbe] Endpoint configuration error: %v", err)
		return
	}

	packetBuilder := newProbePacketBuilder(endpoints)

	start := time.Now()
	workerCount := min(len(sessions), cfg.PeerProbe.SessionWorkerCount)
	jobs := make(chan BgpSession, len(sessions))
	results := make(chan bool, len(sessions))

	var wg sync.WaitGroup
	for range workerCount {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for session := range jobs {
				if ctx.Err() != nil {
					results <- false
					continue
				}
				packet, err := packetBuilder(session)
				if err != nil {
					log.Printf("[PeerProbe] Session %s packet build failed: %v", session.UUID, err)
					results <- false
					continue
				}
				if err := probeSession(ctx, session, endpoints, packet); err != nil {
					// log.Printf("[PeerProbe] Session %s probe failed: %v", session.UUID, err)
					results <- false
				} else {
					results <- true
				}
			}
		}()
	}

	for _, session := range sessions {
		jobs <- session
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

	log.Printf("[PeerProbe] Probed %d succeeded of %d enabled sessions using %d workers in %v", success, len(sessions), workerCount, time.Since(start))
}

func finalizePeerProbeRun(ctx context.Context) {
	if ctx != nil && ctx.Err() != nil {
		return
	}

	_, err := refreshProbeSummariesWithCooldown(ctx)
	if err != nil {
		if errors.Is(err, context.Canceled) {
			return
		}
		log.Printf("[PeerProbe] Failed to refresh probe summaries: %v", err)
		return
	}
}

func collectProbeCandidateSessions() []BgpSession {
	sessionMutex.RLock()
	defer sessionMutex.RUnlock()

	sessions := make([]BgpSession, 0, len(localSessions))
	for _, s := range localSessions {
		if s.Status == PEERING_STATUS_ENABLED || s.Status == PEERING_STATUS_PROBLEM {
			sessions = append(sessions, s)
		}
	}
	return sessions
}

type peerProbeEndpoints struct {
	srcIPv4    net.IP
	srcIPv6    net.IP
	serverIPv4 net.IP
	serverIPv6 net.IP
	port       int
}

func buildPeerProbeEndpoints() (peerProbeEndpoints, error) {
	var ep peerProbeEndpoints
	ep.port = cfg.PeerAPI.ProbeServerPort

	if cfg.IP.IPv4 != "" {
		ip := net.ParseIP(cfg.IP.IPv4)
		if ip == nil || ip.To4() == nil {
			return ep, fmt.Errorf("invalid peerProbe.srcIpv4: %s", cfg.IP.IPv4)
		}
		ep.srcIPv4 = ip.To4()
	}
	if cfg.IP.IPv6 != "" {
		ip := net.ParseIP(cfg.IP.IPv6)
		if ip == nil || ip.To16() == nil {
			return ep, fmt.Errorf("invalid peerProbe.srcIpv6: %s", cfg.IP.IPv6)
		}
		ep.srcIPv6 = ip.To16()
	}

	if cfg.PeerAPI.ProbeServerIPv4 != "" {
		ip := net.ParseIP(cfg.PeerAPI.ProbeServerIPv4)
		if ip == nil || ip.To4() == nil {
			return ep, fmt.Errorf("invalid peerApiCenter.probeServerIPv4: %s", cfg.PeerAPI.ProbeServerIPv4)
		}
		ep.serverIPv4 = ip.To4()
	}
	if cfg.PeerAPI.ProbeServerIPv6 != "" {
		ip := net.ParseIP(cfg.PeerAPI.ProbeServerIPv6)
		if ip == nil || ip.To16() == nil {
			return ep, fmt.Errorf("invalid peerApiCenter.probeServerIPv6: %s", cfg.PeerAPI.ProbeServerIPv6)
		}
		ep.serverIPv6 = ip.To16()
	}

	if ep.serverIPv4 == nil && ep.serverIPv6 == nil {
		return ep, errors.New("at least one probe server IP must be configured")
	}

	return ep, nil
}

func probeSession(ctx context.Context, session BgpSession, ep peerProbeEndpoints, packet []byte) error {
	needsV4, needsV6 := determineProbeFamilies(session)
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
			err := dispatchProbes(ctx, "udp4", ep.srcIPv4, ep.serverIPv4, ep.port, session.Interface, packet)
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
			err := dispatchProbes(ctx, "udp6", ep.srcIPv6, ep.serverIPv6, ep.port, session.Interface, packet)
			combined = errors.Join(combined, err)
		}
	}

	return combined
}

func determineProbeFamilies(session BgpSession) (bool, bool) {
	mpbgp := slices.Contains(session.Extensions, "mp-bgp")
	hasIPv4 := session.IPv4 != "" || mpbgp
	hasIPv6 := session.IPv6 != "" || session.IPv6LinkLocal != "" || mpbgp
	return hasIPv4, hasIPv6
}

type probePacketBuilder func(session BgpSession) ([]byte, error)

func newProbePacketBuilder(ep peerProbeEndpoints) probePacketBuilder {
	bannerBytes := append([]byte(cfg.PeerProbe.ProbePacketBanner), 0)
	ipv4LE := encodeIPv4LittleEndian(ep.srcIPv4)
	ipv6LE := encodeIPv6LittleEndian(ep.srcIPv6)

	return func(session BgpSession) ([]byte, error) {
		if peerProbeAEAD == nil {
			return nil, errors.New("peer probe encryption key is not initialized")
		}

		payload := &bytes.Buffer{}
		timestamp := uint64(time.Now().UTC().Unix())
		if err := binary.Write(payload, binary.LittleEndian, timestamp); err != nil {
			return nil, fmt.Errorf("write timestamp: %w", err)
		}
		payload.WriteString(cfg.PeerAPI.RouterUUID)
		payload.WriteByte(0)
		payload.WriteString(session.UUID)
		payload.WriteByte(0)
		if session.ASN > math.MaxUint32 {
			return nil, fmt.Errorf("session %s ASN %d exceeds uint32", session.UUID, session.ASN)
		}
		var asnField [4]byte
		binary.LittleEndian.PutUint32(asnField[:], uint32(session.ASN))
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
		// length: header + length field + banner + nonceSize(uint32 LE) + nonce + encrypted payload + footer
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

func dispatchProbes(ctx context.Context, network string, srcIP, dstIP net.IP, port int, iface string, packet []byte) error {
	if iface == "" {
		return errors.New("session interface is required for probe")
	}

	delay := time.Duration(cfg.PeerProbe.ProbePacketIntervalMs) * time.Millisecond
	if delay <= 0 {
		delay = 100 * time.Millisecond
	}

	var combined error
	for i := 0; i < cfg.PeerProbe.ProbePacketCount; i++ {
		if err := sendSingleProbe(ctx, dstIP, port, srcIP, iface, packet); err != nil {
			combined = errors.Join(combined, err)
		}
		if i+1 < cfg.PeerProbe.ProbePacketCount {
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

func sendSingleProbe(ctx context.Context, dstIP net.IP, dstPort int, srcIP net.IP, iface string, payload []byte) error {
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

func bindToInterface(fd uintptr, iface string) error {
	if iface == "" {
		return nil
	}
	return unix.SetsockoptString(int(fd), unix.SOL_SOCKET, unix.SO_BINDTODEVICE, iface)
}

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

func deriveAES256Key(input string) ([]byte, error) {
	trimmed := strings.TrimSpace(input)
	if trimmed == "" {
		return nil, errors.New("empty encryption key")
	}

	if key, err := decodeBase64Key(trimmed, base64.StdEncoding); err == nil && len(key) == 32 {
		return key, nil
	}
	if key, err := decodeBase64Key(trimmed, base64.StdEncoding.WithPadding(base64.NoPadding)); err == nil && len(key) == 32 {
		return key, nil
	}

	if decoded, err := hex.DecodeString(strings.TrimPrefix(trimmed, "0x")); err == nil && len(decoded) == 32 {
		key := make([]byte, 32)
		copy(key, decoded)
		return key, nil
	}

	if len(trimmed) == 32 {
		key := make([]byte, 32)
		copy(key, []byte(trimmed))
		return key, nil
	}

	sum := sha256.Sum256([]byte(trimmed))
	key := make([]byte, 32)
	copy(key, sum[:])
	return key, nil
}

func decodeBase64Key(input string, enc *base64.Encoding) ([]byte, error) {
	data, err := enc.DecodeString(input)
	if err != nil {
		return nil, err
	}
	return data, nil
}
