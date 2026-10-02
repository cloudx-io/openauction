package main

import (
	"encoding/json"
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

// TestHandleConnection_AuctionRequestIgnoresUnknownFields: the server decodes an
// auction request that carries a field it does not know, which is what lets a
// host send newer fields to an older enclave. A malformed request is the control
// that shows the decode error is observable here.
func TestHandleConnection_AuctionRequestIgnoresUnknownFields(t *testing.T) {
	tests := []struct {
		name        string
		request     string
		decodeError bool
	}{
		{name: "unknown field", request: `{"type":"auction_request","auction_id":"a1","bids":[],"future_field":{"x":1}}`},
		{name: "malformed request", request: `{"type":"auction_request","auction_id":"a1","bids":"not-a-list"}`, decodeError: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server, peer := net.Pipe()
			t.Cleanup(func() { _ = peer.Close() })
			conn := &requestConn{Conn: server, req: strings.NewReader(tt.request)}

			go testServer(t, 1).handleConnection(conn)

			var response struct {
				Message string `json:"message"`
			}
			assert.NoError(t, json.NewDecoder(peer).Decode(&response))
			assert.Equal(t, tt.decodeError, strings.HasPrefix(response.Message, "Failed to decode auction request"))
		})
	}
}

func TestGetMaxWorkers(t *testing.T) {
	for _, tc := range []struct {
		value   string
		want    int
		wantErr bool
	}{
		{value: "-1", wantErr: true},
		{value: "0", wantErr: true},
		{value: "1", want: 1},
	} {
		t.Run(tc.value, func(t *testing.T) {
			t.Setenv("ENCLAVE_MAX_WORKERS", tc.value)
			got, err := getMaxWorkers()
			if tc.wantErr {
				assert.Error(t, err)
				return
			}
			assert.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}
