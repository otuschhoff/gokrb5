package client

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"time"

	"github.com/otuschhoff/gokrb5/v8/iana/errorcode"
	"github.com/otuschhoff/gokrb5/v8/messages"
)

const (
	maxKDCResponseSize = 16 << 20
	kdcTimeout         = 5 * time.Second
	maxUDPDatagramSize = 65535
	kdcTCPHeaderSize   = 4
)

// SendToKDC performs network actions to send data to the KDC.
func (cl *Client) sendToKDC(b []byte, realm string) ([]byte, error) {
	switch limit := cl.Config.LibDefaults.UDPPreferenceLimit; {
	case limit == 1:
		// 1 means we should always use TCP
		return cl.sendToKDCOnlyTCP(realm, b)
	case len(b) <= limit:
		return cl.sendToKDCUDPFirst(realm, b)
	default:
		return cl.sendToKDCTCPFirst(realm, b)
	}
}

func (cl *Client) sendToKDCOnlyTCP(realm string, b []byte) ([]byte, error) {
	reply, err := cl.sendKDCTCP(realm, b)
	if err == nil {
		return reply, nil
	}
	if e, ok := errors.AsType[messages.KRBError](err); ok {
		return reply, e
	}
	return reply, fmt.Errorf("communication error with KDC via TCP: %w", err)
}

func (cl *Client) sendToKDCUDPFirst(realm string, b []byte) ([]byte, error) {
	reply, errudp := cl.sendKDCUDP(realm, b)
	if errudp == nil {
		return reply, nil
	}
	if e, ok := errors.AsType[messages.KRBError](errudp); ok && e.ErrorCode != errorcode.KRB_ERR_RESPONSE_TOO_BIG {
		return reply, e
	}
	reply, errtcp := cl.sendKDCTCP(realm, b)
	if errtcp == nil {
		return reply, nil
	}
	if e, ok := errors.AsType[messages.KRBError](errtcp); ok {
		return reply, e
	}
	return reply, fmt.Errorf("failed to communicate with KDC via UDP and TCP: %w", errors.Join(errudp, errtcp))
}

func (cl *Client) sendToKDCTCPFirst(realm string, b []byte) ([]byte, error) {
	rb, errtcp := cl.sendKDCTCP(realm, b)
	if errtcp == nil {
		return rb, nil
	}
	if e, ok := errors.AsType[messages.KRBError](errtcp); ok {
		return rb, e
	}
	rb, errudp := cl.sendKDCUDP(realm, b)
	if errudp == nil {
		return rb, nil
	}
	if e, ok := errors.AsType[messages.KRBError](errudp); ok {
		return rb, e
	}
	return rb, fmt.Errorf("failed to communicate with KDC via TCP and UDP: %w", errors.Join(errtcp, errudp))
}

// sendKDCUDP sends bytes to the KDC via UDP.
func (cl *Client) sendKDCUDP(realm string, b []byte) ([]byte, error) {
	var r []byte
	_, kdcs, err := cl.Config.GetKDCs(realm, false)
	if err != nil {
		return r, fmt.Errorf("discover UDP KDCs: %w", err)
	}
	r, err = cl.sendToServers(kdcs, realm, b, false)
	if err != nil {
		return r, err
	}
	return checkForKRBError(r)
}

// dialSendUDP establishes a UDP connection to a KDC.
func dialSendUDP(kdcs map[int]string, b []byte) ([]byte, error) {
	var errs []error
	for i := 1; i <= len(kdcs); i++ {
		conn, err := net.DialTimeout("udp", kdcs[i], kdcTimeout)
		if err != nil {
			errs = append(errs, fmt.Errorf("error establishing connection to %s: %w", kdcs[i], err))
			continue
		}
		if ierr := conn.SetDeadline(time.Now().Add(kdcTimeout)); ierr != nil {
			closeErr := conn.Close()
			errs = append(errs, fmt.Errorf("error setting deadline on connection to %s: %w", kdcs[i], ierr))
			if closeErr != nil {
				errs = append(errs, fmt.Errorf("error closing connection to %s: %w", kdcs[i], closeErr))
			}
			continue
		}
		rb, err := sendUDP(conn, b)
		if err != nil {
			errs = append(errs, fmt.Errorf("error sending to %s: %w", kdcs[i], err))
			continue
		}
		return rb, nil
	}
	return nil, kdcAttemptsError(errs)
}

// sendUDP sends bytes to connection over UDP.
func sendUDP(conn net.Conn, b []byte) ([]byte, error) {
	return exchangeAndClose(conn, b, exchangeUDP)
}

func exchangeUDP(conn net.Conn, b []byte) ([]byte, error) {
	var r []byte
	n, err := conn.Write(b)
	if err != nil {
		return r, fmt.Errorf("error sending to (%s): %w", conn.RemoteAddr().String(), err)
	}
	if n != len(b) {
		return r, fmt.Errorf("error sending to (%s): %w", conn.RemoteAddr().String(), io.ErrShortWrite)
	}
	udpbuf := make([]byte, maxUDPDatagramSize)
	n, err = conn.Read(udpbuf)
	r = udpbuf[:n]
	if err != nil {
		return r, fmt.Errorf("sending over UDP failed to %s: %w", conn.RemoteAddr().String(), err)
	}
	if len(r) < 1 {
		return r, fmt.Errorf("no response data from %s", conn.RemoteAddr().String())
	}
	return r, nil
}

// sendKDCTCP sends bytes to the KDC via TCP.
func (cl *Client) sendKDCTCP(realm string, b []byte) ([]byte, error) {
	var r []byte
	_, kdcs, err := cl.Config.GetKDCs(realm, true)
	if err != nil {
		return r, fmt.Errorf("discover TCP KDCs: %w", err)
	}
	r, err = cl.sendToServers(kdcs, realm, b, true)
	if err != nil {
		return r, err
	}
	return checkForKRBError(r)
}

// dialKDCTCP establishes a TCP connection to a KDC.
func dialSendTCP(kdcs map[int]string, b []byte) ([]byte, error) {
	var errs []error
	for i := 1; i <= len(kdcs); i++ {
		conn, err := net.DialTimeout("tcp", kdcs[i], kdcTimeout)
		if err != nil {
			errs = append(errs, fmt.Errorf("error establishing connection to %s: %w", kdcs[i], err))
			continue
		}
		if ierr := conn.SetDeadline(time.Now().Add(kdcTimeout)); ierr != nil {
			closeErr := conn.Close()
			errs = append(errs, fmt.Errorf("error setting deadline on connection to %s: %w", kdcs[i], ierr))
			if closeErr != nil {
				errs = append(errs, fmt.Errorf("error closing connection to %s: %w", kdcs[i], closeErr))
			}
			continue
		}
		rb, err := sendTCP(conn, b)
		if err != nil {
			errs = append(errs, fmt.Errorf("error sending to %s: %w", kdcs[i], err))
			continue
		}
		return rb, nil
	}
	return nil, kdcAttemptsError(errs)
}

// sendTCP sends bytes to connection over TCP.
func sendTCP(conn net.Conn, b []byte) ([]byte, error) {
	return exchangeAndClose(conn, b, exchangeTCP)
}

func exchangeAndClose(conn net.Conn, b []byte, exchange func(net.Conn, []byte) ([]byte, error)) ([]byte, error) {
	reply, err := exchange(conn, b)
	if closeErr := conn.Close(); closeErr != nil {
		return nil, errors.Join(err, fmt.Errorf("close KDC connection: %w", closeErr))
	}
	return reply, err
}

func clientUint32FromInt(name string, value int) (uint32, error) {
	if value < 0 || uint64(value) > math.MaxUint32 { // #nosec G115 -- nonnegative branch is bounded before conversion.
		return 0, fmt.Errorf("%s %d exceeds uint32 range", name, value)
	}
	return uint32(value), nil // #nosec G115 -- bounded by MaxUint32 above.
}

func clientUint16FromInt(name string, value int) (uint16, error) {
	if value < 0 || value > math.MaxUint16 {
		return 0, fmt.Errorf("%s %d exceeds uint16 range", name, value)
	}
	return uint16(value), nil
}

func kdcAttemptsError(attempts []error) error {
	if len(attempts) == 0 {
		return errors.New("no KDC servers configured")
	}
	return fmt.Errorf("error sending Kerberos message: %w", errors.Join(attempts...))
}

func exchangeTCP(conn net.Conn, b []byte) ([]byte, error) {
	var r []byte
	if uint64(len(b)) > math.MaxUint32 {
		return nil, errors.New("KDC request exceeds the TCP frame size")
	}
	// RFC 4120 7.2.2 specifies the first 4 bytes indicate the length of the message in big endian order.
	hb := make([]byte, kdcTCPHeaderSize, kdcTCPHeaderSize+len(b))
	length, err := clientUint32FromInt("KDC TCP frame length", len(b))
	if err != nil {
		return nil, err
	}
	binary.BigEndian.PutUint32(hb, length)
	b = append(hb, b...)

	if _, err := io.Copy(conn, bytes.NewReader(b)); err != nil {
		return r, fmt.Errorf("error sending to KDC (%s): %w", conn.RemoteAddr().String(), err)
	}

	sh := make([]byte, kdcTCPHeaderSize)
	if _, err := io.ReadFull(conn, sh); err != nil {
		return r, fmt.Errorf("error reading response size header: %w", err)
	}
	s := binary.BigEndian.Uint32(sh)
	if s == 0 {
		return r, fmt.Errorf("no response data from KDC %s", conn.RemoteAddr().String())
	}
	if s > maxKDCResponseSize {
		return r, fmt.Errorf("KDC response from %s exceeds %d bytes", conn.RemoteAddr().String(), maxKDCResponseSize)
	}

	rb := make([]byte, s)
	if _, err := io.ReadFull(conn, rb); err != nil {
		return r, fmt.Errorf("error reading response: %w", err)
	}
	return rb, nil
}

// checkForKRBError checks if the response bytes from the KDC are a KRBError.
func checkForKRBError(b []byte) ([]byte, error) {
	var KRBErr messages.KRBError
	if err := KRBErr.Unmarshal(b); err == nil {
		return b, KRBErr
	}
	return b, nil
}
