package bird

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
)

// BirdConn wraps a single control connection to the BIRD daemon.
type BirdConn struct {
	conn net.Conn
	rdr  *bufio.Reader
	mu   sync.Mutex
}

// NewBirdConnection opens a fresh UNIX socket connection to BIRD and drops the
// greeting banner so subsequent reads only contain command output.
func NewBirdConnection(unixPath string) (*BirdConn, error) {
	conn, err := net.Dial("unix", unixPath)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to bird socket: %w", err)
	}

	bc := &BirdConn{
		conn: conn,
		rdr:  bufio.NewReader(conn),
	}

	// Remove the initial banner before the caller issues commands.
	bc.Read(nil)
	return bc, nil
}

// Read consumes output lines from the socket, removes the numeric status
// prefix, and forwards the remaining text to outputBuffer when provided.
func (b *BirdConn) Read(outputBuffer io.Writer) {
	if b == nil {
		return
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	if b.conn == nil {
		return
	}
	if b.rdr == nil {
		b.rdr = bufio.NewReader(b.conn)
	}

	const (
		statusDigits = 4
		newline      = '\n'
	)

	for {
		line, err := b.rdr.ReadBytes(newline)
		if err != nil {
			break
		}

		// Check if the line starts with a status number
		if len(line) > statusDigits && isNumeric(line[0]) && isNumeric(line[1]) && isNumeric(line[2]) && isNumeric(line[3]) {
			// Ensure there's content after the status number
			if outputBuffer != nil && len(line) > statusDigits+1 {
				outputBuffer.Write(line[statusDigits+1:])
			}
			// Status indicates no more lines could be read
			if line[0] == '0' || line[0] == '8' || line[0] == '9' {
				break
			}
			continue
		}

		if outputBuffer != nil && len(line) > 1 {
			// Removes starting space and outputs the rest
			outputBuffer.Write(line[1:])
		}
	}
}

// Write sends a command (plus newline) to the socket.
func (b *BirdConn) Write(cmd string) error {
	if b == nil {
		return fmt.Errorf("BirdConn is nil")
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	if b.conn == nil {
		return fmt.Errorf("connection is nil")
	}

	if _, err := b.conn.Write([]byte(cmd + "\n")); err != nil {
		return fmt.Errorf("failed to write command: %w", err)
	}
	return nil
}

// Close terminates the underlying socket.
func (b *BirdConn) Close() error {
	if b == nil {
		return nil
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	if b.conn == nil {
		return nil
	}

	err := b.conn.Close()
	b.conn = nil
	b.rdr = nil
	if err != nil {
		return fmt.Errorf("failed to close bird socket: %w", err)
	}
	return nil
}

// Restrict switches the CLI session into restricted mode.
func (b *BirdConn) Restrict() (bool, error) {
	if err := b.Write("restrict"); err != nil {
		return false, fmt.Errorf("failed to send restrict command: %w", err)
	}

	var buf bytes.Buffer
	b.Read(&buf)
	return strings.Contains(buf.String(), "Access restricted"), nil
}

func isNumeric(b byte) bool {
	return b >= '0' && b <= '9'
}
