package service

import (
	"crypto/tls"
	"net"
	"net/http"
	"time"
	"strings"

	"github.com/traefik/traefik/v3/pkg/config/dynamic"
	"golang.org/x/net/http/httpguts"
	"golang.org/x/net/http2"
)

func newSmartRoundTripper(transport *http.Transport, forwardingTimeouts *dynamic.ForwardingTimeouts) (*smartRoundTripper, error) {
	transportHTTP1 := transport.Clone()

	transportHTTP2, err := http2.ConfigureTransports(transport)
	if err != nil {
		return nil, err
	}

	if forwardingTimeouts != nil {
		transportHTTP2.ReadIdleTimeout = time.Duration(forwardingTimeouts.ReadIdleTimeout)
		transportHTTP2.PingTimeout = time.Duration(forwardingTimeouts.PingTimeout)
	}

	transportH2C := &h2cTransportWrapper{
		Transport: &http2.Transport{
			DialTLS: func(network, addr string, cfg *tls.Config) (net.Conn, error) {
				return net.Dial(network, addr)
			},
			AllowHTTP: true,
		},
	}

	if forwardingTimeouts != nil {
		transportH2C.ReadIdleTimeout = time.Duration(forwardingTimeouts.ReadIdleTimeout)
		transportH2C.PingTimeout = time.Duration(forwardingTimeouts.PingTimeout)
	}

	transport.RegisterProtocol("h2c", transportH2C)

	return &smartRoundTripper{
		http2: transport,
		http:  transportHTTP1,
	}, nil
}

// smartRoundTripper implements RoundTrip while making sure that HTTP/2 is not used
// with protocols that start with a Connection Upgrade, such as SPDY or Websocket.
type smartRoundTripper struct {
	http2 *http.Transport
	http  *http.Transport
}

func (m *smartRoundTripper) Clone() http.RoundTripper {
	h := m.http.Clone()
	h2 := m.http2.Clone()
	return &smartRoundTripper{http: h, http2: h2}
}

func (m *smartRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	if cfViewerAddress := req.Header.Get("Cloudfront-Viewer-Address"); cfViewerAddress != "" {
		clientIp := ipAddressWithoutPort(cfViewerAddress)
		req.Header.Set("X-Forwarded-For", clientIp)
		req.Header.Set("X-Real-Ip", clientIp)
	}

	if cfForwardedProto := req.Header.Get("Cloudfront-Forwarded-Proto"); cfForwardedProto != "" {
		req.Header.Set("X-Forwarded-Proto", cfForwardedProto)
	}

	// If we have a connection upgrade, we don't use HTTP/2
	if httpguts.HeaderValuesContainsToken(req.Header["Connection"], "Upgrade") {
		return m.http.RoundTrip(req)
	}

	return m.http2.RoundTrip(req)
}

func ipAddressWithoutPort(input string) string {
	parts := strings.Split(input, ":")

	if len(parts) < 2 {
		return input
	}

	// IPv6 address contains more than one ":"
	isIPv6 := len(parts) > 2

	// Remove the last part (port)
	addressParts := parts[:len(parts)-1]

	// Reassemble
	var address string
	if isIPv6 {
		address = strings.Join(addressParts, ":")
	} else {
		address = addressParts[0]
	}

	return address
}
