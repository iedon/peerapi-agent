package bird

import (
	"bytes"
	"errors"
	"fmt"
	"sync"
	"time"
)

const (
	defaultAcquireTimeout = 5 * time.Second
	defaultIdleTTL        = 3 * time.Minute
	maintenanceInterval   = 20 * time.Second
)

var (
	errPoolClosed     = errors.New("bird: connection pool closed")
	errPoolAtCapacity = errors.New("bird: pool at capacity")
)

// PooledConnection represents a managed connection slot.
type PooledConnection struct {
	conn      *BirdConn
	lastUsed  time.Time
	inUse     bool
	broken    bool
	discarded bool
	mu        sync.Mutex
}

// BirdPool maintains a pool of long-lived connections to the BIRD control socket.
type BirdPool struct {
	socketPath  string
	minSize     int
	maxSize     int
	maxRetries  int
	retryDelay  time.Duration
	waitTimeout time.Duration
	idleTTL     time.Duration
	maintEvery  time.Duration
	available   chan *PooledConnection
	shutdown    chan struct{}
	closeOnce   sync.Once
	maintWG     sync.WaitGroup
	mu          sync.Mutex
	conns       map[*PooledConnection]struct{}
}

// NewBirdPool builds a new connection pool and pre-warms it with minSize connections.
func NewBirdPool(socketPath string, poolSize, poolSizeMax, connectionMaxRetries, connectionRetryDelayMs int) (*BirdPool, error) {
	if poolSize <= 0 {
		poolSize = 1
	}
	if poolSizeMax < poolSize {
		poolSizeMax = poolSize * 4
	}
	if connectionMaxRetries <= 0 {
		connectionMaxRetries = 1
	}

	retryDelay := time.Duration(connectionRetryDelayMs) * time.Millisecond
	if retryDelay <= 0 {
		retryDelay = 200 * time.Millisecond
	}

	bp := &BirdPool{
		socketPath:  socketPath,
		minSize:     poolSize,
		maxSize:     poolSizeMax,
		maxRetries:  connectionMaxRetries,
		retryDelay:  retryDelay,
		waitTimeout: defaultAcquireTimeout,
		idleTTL:     defaultIdleTTL,
		maintEvery:  maintenanceInterval,
		available:   make(chan *PooledConnection, poolSizeMax),
		shutdown:    make(chan struct{}),
		conns:       make(map[*PooledConnection]struct{}, poolSizeMax),
	}

	for i := 0; i < bp.minSize; i++ {
		pc, err := bp.checkoutFresh(false)
		if err != nil {
			bp.Close()
			return nil, fmt.Errorf("failed to initialize bird pool (conn %d): %w", i+1, err)
		}
		bp.enqueue(pc)
	}

	bp.maintWG.Add(1)
	go bp.maintain()
	return bp, nil
}

// GetConnection returns an exclusive connection slot from the pool.
func (bp *BirdPool) GetConnection() (*PooledConnection, error) {
	timer := time.NewTimer(bp.waitTimeout)
	defer timer.Stop()

	for {
		if pc := bp.tryAcquireAvailable(); pc != nil {
			if err := bp.ensureHealthyConn(pc); err != nil {
				bp.discard(pc)
				continue
			}
			return pc, nil
		}

		pc, err := bp.checkoutFresh(true)
		if err == nil {
			return pc, nil
		}
		if errors.Is(err, errPoolAtCapacity) {
			select {
			case <-bp.shutdown:
				return nil, errPoolClosed
			case <-timer.C:
				return nil, fmt.Errorf("timeout waiting for available bird connection")
			case pc := <-bp.available:
				if pc == nil {
					continue
				}
				if !pc.acquire() {
					continue
				}
				if err := bp.ensureHealthyConn(pc); err != nil {
					bp.discard(pc)
					continue
				}
				return pc, nil
			}
		}
		if errors.Is(err, errPoolClosed) {
			return nil, err
		}
		return nil, err
	}
}

// ReleaseConnection returns a connection to the pool or disposes it when necessary.
func (bp *BirdPool) ReleaseConnection(pc *PooledConnection) {
	if pc == nil {
		return
	}

	pc.mu.Lock()
	if !pc.inUse {
		pc.mu.Unlock()
		return
	}
	pc.inUse = false
	pc.lastUsed = time.Now()
	drop := pc.discarded || pc.conn == nil || pc.broken
	pc.mu.Unlock()

	if drop || bp.isClosed() {
		bp.discard(pc)
		return
	}

	if bp.enqueue(pc) {
		return
	}

	bp.mu.Lock()
	extra := len(bp.conns) > bp.minSize
	bp.mu.Unlock()

	if extra {
		bp.discard(pc)
		return
	}

	select {
	case bp.available <- pc:
	case <-bp.shutdown:
		bp.discard(pc)
	}
}

// Close tears down the pool and all managed connections.
func (bp *BirdPool) Close() {
	bp.closeOnce.Do(func() {
		close(bp.shutdown)
		bp.maintWG.Wait()

		bp.mu.Lock()
		conns := bp.conns
		bp.conns = nil
		bp.mu.Unlock()

		for pc := range conns {
			pc.discard()
		}

		for {
			select {
			case pc := <-bp.available:
				if pc != nil {
					pc.discard()
				}
			default:
				return
			}
		}
	})
}

// WithConnection borrows a connection, executes fn, and retries once on connection errors.
func (bp *BirdPool) WithConnection(fn func(conn *BirdConn) error) error {
	pc, err := bp.GetConnection()
	if err != nil {
		return err
	}
	defer bp.ReleaseConnection(pc)

	if err := bp.ensureHealthyConn(pc); err != nil {
		return err
	}

	if err := fn(pc.conn); err != nil {
		pc.markBroken()
		if healErr := bp.ensureHealthyConn(pc); healErr != nil {
			return err
		}
		return fn(pc.conn)
	}
	return nil
}

// ShowStatus executes "show status" and returns the raw output.
func (bp *BirdPool) ShowStatus() (string, error) {
	var output string
	err := bp.WithConnection(func(conn *BirdConn) error {
		var buf bytes.Buffer
		if err := conn.Write("show status"); err != nil {
			return err
		}
		conn.Read(&buf)
		output = buf.String()
		return nil
	})
	return output, err
}

// Configure reloads the BIRD configuration using a dedicated ephemeral connection.
func (bp *BirdPool) Configure() (bool, error) {
	bc, err := NewBirdConnection(bp.socketPath)
	if err != nil {
		return false, err
	}
	defer bc.Close()

	if err := bc.Write("configure"); err != nil {
		return false, err
	}
	bc.Read(nil)
	return true, nil
}

// GetProtocolStatus runs the "show protocols all <session>" command and parses its output.
func (bp *BirdPool) GetProtocolStatus(sessionName string) (string, string, string, int64, int64, int64, int64, error) {
	var output string
	err := bp.WithConnection(func(conn *BirdConn) error {
		var buf bytes.Buffer
		buf.Grow(4096)
		if err := conn.Write("show protocols all " + sessionName); err != nil {
			return err
		}
		conn.Read(&buf)
		output = buf.String()
		return nil
	})
	if err != nil {
		return "", "", "", 0, 0, 0, 0, err
	}
	return parseProtocolOutput([]byte(output))
}

func (bp *BirdPool) tryAcquireAvailable() *PooledConnection {
	select {
	case pc := <-bp.available:
		if pc == nil {
			return nil
		}
		if pc.acquire() {
			return pc
		}
		if pc.isDiscarded() {
			return nil
		}
		return nil
	default:
		return nil
	}
}

func (bp *BirdPool) enqueue(pc *PooledConnection) bool {
	if pc == nil {
		return false
	}
	if pc.isDiscarded() {
		return false
	}
	select {
	case bp.available <- pc:
		return true
	default:
		return false
	}
}

func (bp *BirdPool) checkoutFresh(markInUse bool) (*PooledConnection, error) {
	if bp.isClosed() {
		return nil, errPoolClosed
	}

	conn, err := bp.dial()
	if err != nil {
		return nil, err
	}
	pc := newPooledConnection(conn)
	pc.mu.Lock()
	pc.inUse = markInUse
	pc.mu.Unlock()

	bp.mu.Lock()
	if bp.conns == nil {
		bp.conns = make(map[*PooledConnection]struct{})
	}
	if len(bp.conns) >= bp.maxSize {
		bp.mu.Unlock()
		pc.discard()
		return nil, errPoolAtCapacity
	}
	bp.conns[pc] = struct{}{}
	bp.mu.Unlock()
	return pc, nil
}

func (bp *BirdPool) ensureHealthyConn(pc *PooledConnection) error {
	pc.mu.Lock()
	healthy := pc.conn != nil && !pc.broken && !pc.discarded
	pc.mu.Unlock()
	if healthy {
		return nil
	}

	conn, err := bp.dial()
	if err != nil {
		return err
	}
	old := pc.swapConn(conn)
	if old != nil {
		old.Close()
	}
	return nil
}

func (bp *BirdPool) discard(pc *PooledConnection) {
	if pc == nil {
		return
	}
	bp.mu.Lock()
	if bp.conns != nil {
		delete(bp.conns, pc)
	}
	bp.mu.Unlock()
	pc.discard()
}

func (bp *BirdPool) maintain() {
	defer bp.maintWG.Done()
	ticker := time.NewTicker(bp.maintEvery)
	defer ticker.Stop()

	for {
		select {
		case <-bp.shutdown:
			return
		case <-ticker.C:
			bp.reclaimIdle()
			bp.ensureBaseline()
		}
	}
}

func (bp *BirdPool) reclaimIdle() {
	now := time.Now()
	var victims []*PooledConnection

	bp.mu.Lock()
	current := len(bp.conns)
	if current == 0 {
		bp.mu.Unlock()
		return
	}

	for pc := range bp.conns {
		if current-len(victims) <= bp.minSize {
			break
		}
		pc.mu.Lock()
		idle := now.Sub(pc.lastUsed)
		drop := pc.discarded || (!pc.inUse && (pc.conn == nil || pc.broken || idle > bp.idleTTL))
		pc.mu.Unlock()
		if drop {
			victims = append(victims, pc)
		}
	}

	for _, pc := range victims {
		delete(bp.conns, pc)
	}
	bp.mu.Unlock()

	for _, pc := range victims {
		pc.discard()
	}
}

func (bp *BirdPool) ensureBaseline() {
	for {
		bp.mu.Lock()
		need := bp.minSize - len(bp.conns)
		bp.mu.Unlock()
		if need <= 0 {
			return
		}
		pc, err := bp.checkoutFresh(false)
		if err != nil {
			if errors.Is(err, errPoolClosed) {
				return
			}
			time.Sleep(bp.retryDelay)
			continue
		}
		bp.enqueue(pc)
	}
}

func (bp *BirdPool) dial() (*BirdConn, error) {
	attempts := bp.maxRetries
	if attempts <= 0 {
		attempts = 1
	}
	var lastErr error
	for i := 0; i < attempts; i++ {
		if bp.isClosed() {
			return nil, errPoolClosed
		}
		conn, err := NewBirdConnection(bp.socketPath)
		if err != nil {
			lastErr = err
		} else {
			ok, err := conn.Restrict()
			if err != nil {
				lastErr = err
				conn.Close()
			} else if !ok {
				lastErr = fmt.Errorf("failed to enter restricted mode")
				conn.Close()
			} else {
				return conn, nil
			}
		}
		if i < attempts-1 {
			select {
			case <-bp.shutdown:
				return nil, errPoolClosed
			case <-time.After(bp.retryDelay):
			}
		}
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("unknown dial error")
	}
	return nil, lastErr
}

func (bp *BirdPool) isClosed() bool {
	select {
	case <-bp.shutdown:
		return true
	default:
		return false
	}
}

func newPooledConnection(conn *BirdConn) *PooledConnection {
	return &PooledConnection{
		conn:     conn,
		lastUsed: time.Now(),
	}
}

func (pc *PooledConnection) acquire() bool {
	pc.mu.Lock()
	defer pc.mu.Unlock()
	if pc.inUse || pc.discarded {
		return false
	}
	pc.inUse = true
	return true
}

func (pc *PooledConnection) isDiscarded() bool {
	pc.mu.Lock()
	defer pc.mu.Unlock()
	return pc.discarded
}

func (pc *PooledConnection) markBroken() {
	pc.mu.Lock()
	if pc.discarded {
		pc.mu.Unlock()
		return
	}
	old := pc.conn
	pc.conn = nil
	pc.broken = true
	pc.mu.Unlock()
	if old != nil {
		old.Close()
	}
}

func (pc *PooledConnection) swapConn(conn *BirdConn) *BirdConn {
	pc.mu.Lock()
	defer pc.mu.Unlock()
	old := pc.conn
	pc.conn = conn
	pc.broken = false
	pc.discarded = false
	pc.lastUsed = time.Now()
	return old
}

func (pc *PooledConnection) discard() {
	pc.mu.Lock()
	if pc.discarded {
		pc.mu.Unlock()
		return
	}
	old := pc.conn
	pc.conn = nil
	pc.inUse = false
	pc.broken = true
	pc.discarded = true
	pc.mu.Unlock()
	if old != nil {
		old.Close()
	}
}
