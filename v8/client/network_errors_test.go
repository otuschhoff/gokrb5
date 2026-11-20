package client

import (
	"bytes"
	"errors"
	"io"
	"net"
	"os"
	"testing"
	"time"
)

type faultConn struct {
	reader   io.Reader
	readErr  error
	writeErr error
	closeErr error
	short    bool
	closes   int
}

func (c *faultConn) Read(p []byte) (int, error) {
	if c.readErr != nil {
		return 0, c.readErr
	}
	return c.reader.Read(p)
}

func (c *faultConn) Write(p []byte) (int, error) {
	if c.writeErr != nil {
		return 0, c.writeErr
	}
	if c.short {
		return len(p) - 1, nil
	}
	return len(p), nil
}
func (c *faultConn) Close() error                   { c.closes++; return c.closeErr }
func (*faultConn) LocalAddr() net.Addr              { return new(net.TCPAddr) }
func (*faultConn) RemoteAddr() net.Addr             { return new(net.TCPAddr) }
func (*faultConn) SetDeadline(time.Time) error      { return nil }
func (*faultConn) SetReadDeadline(time.Time) error  { return nil }
func (*faultConn) SetWriteDeadline(time.Time) error { return nil }

func TestKDCExchangeErrorIdentityAndOwnership(t *testing.T) {
	primary := errors.New("injected network failure")
	cleanup := errors.New("injected close failure")
	deadline := &net.OpError{Op: "read", Net: "tcp", Source: nil, Addr: nil, Err: os.ErrDeadlineExceeded}
	tests := []struct {
		name string
		conn func(*faultConn)
		want error
	}{
		{name: "write", conn: func(c *faultConn) { c.writeErr = primary }, want: primary},
		{name: "short write", conn: func(c *faultConn) { c.short = true }, want: io.ErrShortWrite},
		{name: "read", conn: func(c *faultConn) { c.readErr = primary }, want: primary},
		{name: "timeout", conn: func(c *faultConn) { c.readErr = deadline }, want: os.ErrDeadlineExceeded},
		{name: "close", conn: func(c *faultConn) { c.closeErr = cleanup }, want: cleanup},
		{
			name: "primary and close",
			conn: func(c *faultConn) { c.readErr, c.closeErr = primary, cleanup },
			want: primary,
		},
	}
	for _, protocol := range []struct {
		name string
		send func(net.Conn, []byte) ([]byte, error)
		wire []byte
	}{
		{name: "TCP", send: sendTCP, wire: []byte{0, 0, 0, 1, 'x'}},
		{name: "UDP", send: sendUDP, wire: []byte{'x'}},
	} {
		t.Run(protocol.name, func(t *testing.T) {
			for _, tt := range tests {
				t.Run(tt.name, func(t *testing.T) {
					var conn faultConn
					tt.conn(&conn)
					conn.reader = bytes.NewReader(protocol.wire)
					_, err := protocol.send(&conn, []byte("request"))
					if !errors.Is(err, tt.want) || conn.closes != 1 {
						t.Fatalf("exchange = %v, closes = %d; want %v and one close", err, conn.closes, tt.want)
					}
					if conn.closeErr != nil && !errors.Is(err, conn.closeErr) {
						t.Fatal("cleanup failure was lost")
					}
				})
			}
		})
	}
}

func TestKDCFailoverRetainsFirstTypedCause(t *testing.T) {
	first := &net.OpError{Op: "first endpoint", Net: "", Source: nil, Addr: nil, Err: os.ErrDeadlineExceeded}
	last := &net.OpError{Op: "last endpoint", Net: "", Source: nil, Addr: nil, Err: os.ErrPermission}
	err := kdcAttemptsError([]error{first, last})
	got, ok := errors.AsType[*net.OpError](err)
	if !ok || got != first || !errors.Is(err, os.ErrPermission) || !got.Timeout() {
		t.Fatalf("endpoint failure order or identity lost: %v", err)
	}
	if err := kdcAttemptsError(nil); err == nil {
		t.Fatal("empty KDC list reported success")
	}
}

func TestSendUDPDoesNotTruncateLargeDatagram(t *testing.T) {
	want := bytes.Repeat([]byte{1}, 5000)
	var conn faultConn
	conn.reader = bytes.NewReader(want)
	got, err := sendUDP(&conn, []byte("request"))
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("UDP received %d bytes, %v; want %d", len(got), err, len(want))
	}
}

func TestKDCTruncatedFrameErrorIdentity(t *testing.T) {
	var conn faultConn
	conn.reader = bytes.NewReader([]byte{0, 0, 0, 5, 1})
	if _, err := sendTCP(&conn, []byte("request")); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("truncated response = %v, want unexpected EOF", err)
	}
}
