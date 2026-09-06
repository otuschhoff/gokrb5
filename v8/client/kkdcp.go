package client

import (
	"bytes"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strings"

	"github.com/otuschhoff/gokrb5/v8/types"
)

const (
	kkdcpContentType     = "application/kerberos"
	maxKKDCPResponseSize = 16 << 20
)

func isKKDCPServer(server string) bool {
	u, err := url.Parse(server)
	return err == nil && strings.EqualFold(u.Scheme, "https") && u.Host != ""
}

func (cl *Client) sendKKDCP(proxyURL, realm string, message []byte) ([]byte, error) {
	if !isKKDCPServer(proxyURL) {
		return nil, fmt.Errorf("invalid KKDCP HTTPS URL %q", proxyURL)
	}
	proxyMessage, err := types.NewKDCProxyMessage(message, realm, 0)
	if err != nil {
		return nil, err
	}
	body, err := proxyMessage.Marshal()
	if err != nil {
		return nil, fmt.Errorf("marshal KKDCP request: %w", err)
	}
	req, err := http.NewRequest(http.MethodPost, proxyURL, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("create KKDCP request: %w", err)
	}
	req.Header.Set("Content-Type", kkdcpContentType)
	req.Header.Set("Accept", kkdcpContentType)
	httpClient := *cl.settings.httpClient()
	httpClient.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
		return http.ErrUseLastResponse
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("send KKDCP request to %s: %w", proxyURL, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		if _, drainErr := io.Copy(io.Discard, io.LimitReader(resp.Body, 4096)); drainErr != nil {
			return nil, fmt.Errorf("KKDCP server %s returned HTTP status %s; drain response body: %w", proxyURL, resp.Status, drainErr)
		}
		return nil, fmt.Errorf("KKDCP server %s returned HTTP status %s", proxyURL, resp.Status)
	}
	mediaType, _, err := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if err != nil || !strings.EqualFold(mediaType, kkdcpContentType) {
		return nil, fmt.Errorf("KKDCP server %s returned content type %q", proxyURL, resp.Header.Get("Content-Type"))
	}
	encoded, err := io.ReadAll(io.LimitReader(resp.Body, maxKKDCPResponseSize+1))
	if err != nil {
		return nil, fmt.Errorf("read KKDCP response from %s: %w", proxyURL, err)
	}
	if len(encoded) > maxKKDCPResponseSize {
		return nil, fmt.Errorf("KKDCP response from %s exceeds %d bytes", proxyURL, maxKKDCPResponseSize)
	}
	var proxyReply types.KDCProxyMessage
	if err := proxyReply.Unmarshal(encoded); err != nil {
		return nil, fmt.Errorf("decode KKDCP response from %s: %w", proxyURL, err)
	}
	reply, err := proxyReply.KerberosMessage()
	if err != nil {
		return nil, fmt.Errorf("decode KKDCP Kerberos response from %s: %w", proxyURL, err)
	}
	return reply, nil
}

func (cl *Client) sendToServers(servers map[int]string, realm string, message []byte, tcp bool) ([]byte, error) {
	var errs []string
	for i := 1; i <= len(servers); i++ {
		server := servers[i]
		var (
			reply []byte
			err   error
		)
		if strings.Contains(server, "://") {
			reply, err = cl.sendKKDCP(server, realm, message)
		} else if tcp {
			reply, err = dialSendTCP(map[int]string{1: server}, message)
		} else {
			reply, err = dialSendUDP(map[int]string{1: server}, message)
		}
		if err == nil {
			return reply, nil
		}
		errs = append(errs, fmt.Sprintf("%s: %v", server, err))
	}
	return nil, fmt.Errorf("error sending Kerberos message: %s", strings.Join(errs, "; "))
}
