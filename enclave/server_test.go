package main

import (
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/peterldowns/testy/assert"
)

// requestConn serves a fixed request on Read and passes writes and deadlines
// through to the embedded conn.
type requestConn struct {
	net.Conn
	req io.Reader
}

func (c *requestConn) Read(p []byte) (int, error) { return c.req.Read(p) }

// readDeadlineFailConn fails SetReadDeadline and records any Read.
type readDeadlineFailConn struct {
	net.Conn
	read bool
}

func (*readDeadlineFailConn) SetReadDeadline(time.Time) error {
	return errors.New("set read deadline failed")
}

func (c *readDeadlineFailConn) Read([]byte) (int, error) {
	c.read = true
	return 0, io.EOF
}

func TestHandleConnection_WriteDeadlineReleasesStalledPeer(t *testing.T) {
	orig := writeTimeout
	writeTimeout = 50 * time.Millisecond
	t.Cleanup(func() { writeTimeout = orig })

	// net.Pipe is unbuffered, so the response write blocks until the peer reads.
	// The peer never reads.
	server, peer := net.Pipe()
	t.Cleanup(func() { _ = peer.Close() })
	conn := &requestConn{Conn: server, req: strings.NewReader(`{"type":"ping"}`)}
	s := testServer(t, 1)

	done := make(chan struct{})
	go func() {
		s.handleConnection(conn)
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("handleConnection still blocked writing to a peer that never reads")
	}
}

func TestHandleConnection_ClosesWithoutReadingWhenReadDeadlineFails(t *testing.T) {
	server, peer := net.Pipe()
	t.Cleanup(func() { _ = peer.Close() })
	conn := &readDeadlineFailConn{Conn: server}

	testServer(t, 1).handleConnection(conn)

	assert.False(t, conn.read)
	_, err := server.Write([]byte("x"))
	assert.Error(t, err)
}
