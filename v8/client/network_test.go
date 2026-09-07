package client

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"strings"
	"testing"

	"github.com/otuschhoff/gokrb5/v8/config"
)

func startTCPResponseServer(t *testing.T, response []byte) (*net.TCPAddr, <-chan error) {
	t.Helper()
	listener, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
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
		_, writeErr := io.Copy(connection, bytes.NewReader(response))
		serverErr <- writeErr
	}()
	return listener.Addr().(*net.TCPAddr), serverErr
}

func TestSendTCPResponseFraming(t *testing.T) {
	tests := []struct {
		name     string
		response []byte
		want     []byte
		wantErr  string
	}{
		{name: "success", response: append([]byte{0, 0, 0, 3}, []byte("KDC")...), want: []byte("KDC")},
		{name: "empty", response: []byte{0, 0, 0, 0}, wantErr: "no response data"},
		{name: "truncated header", response: []byte{0, 0}, wantErr: "response size header"},
		{name: "truncated body", response: append([]byte{0, 0, 0, 4}, []byte("KDC")...), wantErr: "reading response"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			address, serverErr := startTCPResponseServer(t, test.response)
			connection, err := net.DialTCP("tcp", nil, address)
			if err != nil {
				t.Fatal(err)
			}
			got, err := sendTCP(connection, []byte("request"))
			if test.wantErr == "" {
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(got, test.want) {
					t.Fatalf("response = %q, want %q", got, test.want)
				}
			} else if err == nil || !strings.Contains(err.Error(), test.wantErr) {
				t.Fatalf("response error = %v, want substring %q", err, test.wantErr)
			}
			if err := <-serverErr; err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestSendToKDCTransportSelection(t *testing.T) {
	t.Run("forced TCP", func(t *testing.T) {
		address, serverErr := startTCPResponseServer(t, append([]byte{0, 0, 0, 3}, []byte("KDC")...))
		cfg := config.New()
		cfg.LibDefaults.UDPPreferenceLimit = 1
		cfg.Realms = []config.Realm{{Realm: "EXAMPLE.ORG", KDC: []string{address.String()}}}
		client := NewWithPassword("user", "EXAMPLE.ORG", "password", cfg)
		response, err := client.sendToKDC([]byte("request"), "EXAMPLE.ORG")
		if err != nil || string(response) != "KDC" {
			t.Fatalf("forced TCP response = %q, %v", response, err)
		}
		if err := <-serverErr; err != nil {
			t.Fatal(err)
		}
	})

	t.Run("TCP failure falls back to UDP", func(t *testing.T) {
		server, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
		if err != nil {
			t.Fatal(err)
		}
		defer server.Close()
		serverErr := make(chan error, 1)
		go func() {
			request := make([]byte, 32)
			_, clientAddress, readErr := server.ReadFromUDP(request)
			if readErr != nil {
				serverErr <- readErr
				return
			}
			_, writeErr := server.WriteToUDP([]byte("KDC"), clientAddress)
			serverErr <- writeErr
		}()
		cfg := config.New()
		cfg.LibDefaults.UDPPreferenceLimit = 4
		cfg.Realms = []config.Realm{{Realm: "EXAMPLE.ORG", KDC: []string{server.LocalAddr().String()}}}
		client := NewWithPassword("user", "EXAMPLE.ORG", "password", cfg)
		response, err := client.sendToKDC([]byte("request"), "EXAMPLE.ORG")
		if err != nil || string(response) != "KDC" {
			t.Fatalf("TCP-to-UDP response = %q, %v", response, err)
		}
		if err := <-serverErr; err != nil {
			t.Fatal(err)
		}
	})
}

func TestSendUDPSuccess(t *testing.T) {
	server, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	serverErr := make(chan error, 1)
	go func() {
		request := make([]byte, 32)
		n, clientAddress, readErr := server.ReadFromUDP(request)
		if readErr != nil {
			serverErr <- readErr
			return
		}
		if string(request[:n]) != "request" {
			serverErr <- io.ErrUnexpectedEOF
			return
		}
		_, writeErr := server.WriteToUDP([]byte("KDC"), clientAddress)
		serverErr <- writeErr
	}()

	connection, err := net.DialUDP("udp", nil, server.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	response, err := sendUDP(connection, []byte("request"))
	if err != nil {
		t.Fatal(err)
	}
	if string(response) != "KDC" {
		t.Fatalf("response = %q, want KDC", response)
	}
	if err := <-serverErr; err != nil {
		t.Fatal(err)
	}
}

func TestDialSendTCPFailover(t *testing.T) {
	response := append([]byte{0, 0, 0, 3}, []byte("KDC")...)
	address, serverErr := startTCPResponseServer(t, response)
	got, err := dialSendTCP(map[int]string{1: ":", 2: address.String()}, []byte("request"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "KDC" {
		t.Fatalf("response = %q, want KDC", got)
	}
	if err := <-serverErr; err != nil {
		t.Fatal(err)
	}
}

func TestDialSendUDPFailover(t *testing.T) {
	server, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	serverErr := make(chan error, 1)
	go func() {
		request := make([]byte, 32)
		_, clientAddress, readErr := server.ReadFromUDP(request)
		if readErr != nil {
			serverErr <- readErr
			return
		}
		_, writeErr := server.WriteToUDP([]byte("KDC"), clientAddress)
		serverErr <- writeErr
	}()

	got, err := dialSendUDP(map[int]string{1: ":", 2: server.LocalAddr().String()}, []byte("request"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "KDC" {
		t.Fatalf("response = %q, want KDC", got)
	}
	if err := <-serverErr; err != nil {
		t.Fatal(err)
	}
}

func TestSendUDPRejectsEmptyResponse(t *testing.T) {
	server, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	serverErr := make(chan error, 1)
	go func() {
		request := make([]byte, 32)
		_, clientAddress, readErr := server.ReadFromUDP(request)
		if readErr != nil {
			serverErr <- readErr
			return
		}
		_, writeErr := server.WriteToUDP(nil, clientAddress)
		serverErr <- writeErr
	}()

	connection, err := net.DialUDP("udp", nil, server.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	_, err = sendUDP(connection, []byte("request"))
	if err == nil || !strings.Contains(err.Error(), "no response data") {
		t.Fatalf("empty UDP response error = %v", err)
	}
	if err := <-serverErr; err != nil {
		t.Fatal(err)
	}
}

func TestSendOnClosedConnections(t *testing.T) {
	udpServer, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	defer udpServer.Close()
	udpConnection, err := net.DialUDP("udp", nil, udpServer.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	if err := udpConnection.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := sendUDP(udpConnection, []byte("request")); err == nil || !strings.Contains(err.Error(), "error sending") {
		t.Fatalf("closed UDP connection error = %v", err)
	}

	tcpListener, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	defer tcpListener.Close()
	tcpConnection, err := net.DialTCP("tcp", nil, tcpListener.Addr().(*net.TCPAddr))
	if err != nil {
		t.Fatal(err)
	}
	if err := tcpConnection.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := sendTCP(tcpConnection, []byte("request")); err == nil || !strings.Contains(err.Error(), "error sending") {
		t.Fatalf("closed TCP connection error = %v", err)
	}
}

func TestDialSendRejectsUnavailableServers(t *testing.T) {
	for name, send := range map[string]func(map[int]string, []byte) ([]byte, error){
		"TCP": dialSendTCP,
		"UDP": dialSendUDP,
	} {
		t.Run(name, func(t *testing.T) {
			_, err := send(map[int]string{1: "invalid"}, []byte("request"))
			if err == nil || !strings.Contains(err.Error(), "error establishing connection") {
				t.Fatalf("unavailable server error = %v", err)
			}
		})
	}
}

func TestSendTCPRejectsOversizedResponse(t *testing.T) {
	header := make([]byte, 4)
	binary.BigEndian.PutUint32(header, maxKDCResponseSize+1)
	address, serverErr := startTCPResponseServer(t, header)
	connection, err := net.DialTCP("tcp", nil, address)
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
