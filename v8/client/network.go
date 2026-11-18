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

const maxKDCResponseSize = 16 << 20

// SendToKDC performs network actions to send data to the KDC.
func (cl *Client) sendToKDC(b []byte, realm string) ([]byte, error) {
	var rb []byte
	if cl.Config.LibDefaults.UDPPreferenceLimit == 1 {
		// 1 means we should always use TCP
		rtcp, errtcp := cl.sendKDCTCP(realm, b)
		if errtcp != nil {
			if e, ok := errors.AsType[messages.KRBError](errtcp); ok {
				return rtcp, e
			}
			return rtcp, fmt.Errorf("communication error with KDC via TCP: %w", errtcp)
		}
		return rtcp, nil
	}
	if len(b) <= cl.Config.LibDefaults.UDPPreferenceLimit {
		// Try UDP first, TCP second
		rudp, errudp := cl.sendKDCUDP(realm, b)
		if errudp != nil {
			if e, ok := errors.AsType[messages.KRBError](errudp); ok && e.ErrorCode != errorcode.KRB_ERR_RESPONSE_TOO_BIG {
				// Got a KRBError from KDC
				// If this is not a KRB_ERR_RESPONSE_TOO_BIG we will return immediately otherwise will try TCP.
				return rudp, e
			}
			// Try TCP
			r, errtcp := cl.sendKDCTCP(realm, b)
			if errtcp != nil {
				if e, ok := errors.AsType[messages.KRBError](errtcp); ok {
					// Got a KRBError
					return r, e
				}
				return r, fmt.Errorf("failed to communicate with KDC via UDP and TCP: %w", errors.Join(errudp, errtcp))
			}
			rudp = r
		}
		return rudp, nil
	}
	// Try TCP first, UDP second
	rb, errtcp := cl.sendKDCTCP(realm, b)
	if errtcp != nil {
		if e, ok := errors.AsType[messages.KRBError](errtcp); ok {
			// Got a KRBError from KDC so returning and not trying UDP.
			return rb, e
		}
		var errudp error
		rb, errudp = cl.sendKDCUDP(realm, b)
		if errudp != nil {
			if e, ok := errors.AsType[messages.KRBError](errudp); ok {
				// Got a KRBError
				return rb, e
			}
			return rb, fmt.Errorf("failed to communicate with KDC via TCP and UDP: %w", errors.Join(errtcp, errudp))
		}
	}
	return rb, nil
}

// sendKDCUDP sends bytes to the KDC via UDP.
func (cl *Client) sendKDCUDP(realm string, b []byte) ([]byte, error) {
	var r []byte
	_, kdcs, err := cl.Config.GetKDCs(realm, false)
	if err != nil {
		return r, err
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
		conn, err := net.DialTimeout("udp", kdcs[i], 5*time.Second)
		if err != nil {
			errs = append(errs, fmt.Errorf("error establishing connection to %s: %w", kdcs[i], err))
			continue
		}
		if ierr := conn.SetDeadline(time.Now().Add(5 * time.Second)); ierr != nil {
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
	udpbuf := make([]byte, 65535)
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
		return r, err
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
		conn, err := net.DialTimeout("tcp", kdcs[i], 5*time.Second)
		if err != nil {
			errs = append(errs, fmt.Errorf("error establishing connection to %s: %w", kdcs[i], err))
			continue
		}
		if ierr := conn.SetDeadline(time.Now().Add(5 * time.Second)); ierr != nil {
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
	hb := make([]byte, 4)
	binary.BigEndian.PutUint32(hb, uint32(len(b)))
	b = append(hb, b...)

	if _, err := io.Copy(conn, bytes.NewReader(b)); err != nil {
		return r, fmt.Errorf("error sending to KDC (%s): %w", conn.RemoteAddr().String(), err)
	}

	sh := make([]byte, 4)
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
