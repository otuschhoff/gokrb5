package client

import (
	"encoding/binary"
	"io"
	"net"
	"strings"
	"testing"
)

func TestSendTCPRejectsOversizedResponse(t *testing.T) {
	listener, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	serverErr := make(chan error, 1)
	go func() {
		connection, acceptErr := listener.AcceptTCP()
		if acceptErr != nil {
			serverErr <- acceptErr
			return
		}
		defer connection.Close()
		header := make([]byte, 4)
		if _, readErr := io.ReadFull(connection, header); readErr != nil {
			serverErr <- readErr
			return
		}
		requestSize := binary.BigEndian.Uint32(header)
		if _, readErr := io.CopyN(io.Discard, connection, int64(requestSize)); readErr != nil {
			serverErr <- readErr
			return
		}
		binary.BigEndian.PutUint32(header, maxKDCResponseSize+1)
		_, writeErr := connection.Write(header)
		serverErr <- writeErr
	}()

	connection, err := net.DialTCP("tcp", nil, listener.Addr().(*net.TCPAddr))
	if err != nil {
		t.Fatal(err)
	}
	_, err = sendTCP(connection, []byte("request"))
	if err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("oversized response error = %v", err)
	}
	if err := <-serverErr; err != nil {
		t.Fatal(err)
	}
}
