// Package connectproxy implements a proxy.ContextDialer which uses HTTP(s) CONNECT
// requests.
//
// It is heavily based on
// https://gist.github.com/jim3ma/3750675f141669ac4702bc9deaf31c6b and meant to
// compliment the proxy package (golang.org/x/net/proxy).
//
// Two URL schemes are supported: http and https.  These represent plaintext
// and TLS-wrapped connections to the proxy server, respectively.
//
// The proxy.ContextDialer returned by the package may either be used directly to make
// connections via a proxy which understands CONNECT request, or indirectly
// via dialer.RegisterDialerType.
//
// Direct use:
//
//	/* Make a proxy.ContextDialer */
//	d, err := connectproxy.New("https://proxyserver:4433", proxy.Direct)
//	if nil != err{
//	        panic(err)
//	}
//
//	/* Connect through it */
//	c, err := d.Dial("tcp", "internalsite.com")
//	if nil != err {
//	        log.Printf("Dial: %v", err)
//	        return
//	}
//
//	/* Do something with c */
//
// Indirectly, via dialer.RegisterDialerType:
//
//	/* Register handlers for HTTP and HTTPS proxies */
//	proxy.RegisterDialerType("http", connectproxy.New)
//	proxy.RegisterDialerType("https", connectproxy.New)
//
//	/* Make a Dialer for a proxy */
//	u, err := url.Parse("https://proxyserver.com:4433")
//	if nil != err {
//	        log.Fatalf("Parse: %v", err)
//	}
//	d, err := proxy.FromURL(u, proxy.Direct)
//	if nil != err {
//	        log.Fatalf("Proxy: %v", err)
//	}
//
//	/* Connect through it */
//	c, err := d.Dial("tcp", "internalsite.com")
//	if nil != err {
//	        log.Fatalf("Dial: %v", err)
//	}
//
//	/* Do something with c */
//
// It's also possible to make the TLS handshake with an HTTPS proxy server use
// a different name for SNI than the Host: header uses in the CONNECT request:
//
//	d, err := NewWithConfig(
//	        "https://sneakyvhost.com:443",
//	        proxy.Direct,
//	        &connectproxy.Config{
//	                ServerName: "normalhoster.com",
//	        },
//	)
//	if nil != err {
//	        panic(err)
//	}
//
//	/* Use d.Dial(...) */
package connectproxy

/*
 * connectproxy.go
 * Implement a dialer which proxies via an HTTP CONNECT request
 * By J. Stuart McMurray
 * Created 20170821
 * Last Modified 20170821
 */

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"time"

	"golang.org/x/net/proxy"
)

// TODO: Define errors as value

// ErrorUnsupportedScheme is returned if a scheme other than "http" or
// "https" is used.
type ErrorUnsupportedScheme error

// ErrorConnectionTimeout is returned if the connection through the proxy
// server was not able to be made before the configured timeout expired.
type ErrorConnectionTimeout error

// Config allows various parameters to be configured.  It is used with
// NewWithConfig.  The config passed to NewWithConfig may be changed between
// requests.  If it is, the changes will affect all current and future
// invocations of the returned proxy.ContextDialer's Dial method.
type Config struct {
	// ServerName is the name to use in the TLS connection to (not through)
	// the proxy server if different from the host in the URL.
	// Specifically, this is used in the ServerName field of the
	// *tls.Config used in connections to TLS-speaking proxy servers.
	ServerName string

	// For proxy servers supporting TLS connections (to, not through),
	// skip TLS certificate validation.
	InsecureSkipVerify bool // Passed directly to tls.Dial

	// Header sets the headers in the initial HTTP CONNECT request.  See
	// the documentation for http.Request for more information.
	Header http.Header

	// DialTimeout is an optional timeout for connections through (not to)
	// the proxy server.
	DialTimeout time.Duration
}

// connectDialer makes connections via an HTTP(s) server supporting the
// CONNECT verb.  It implements the proxy.ContextDialer interface.
type connectDialer struct {
	u       *url.URL
	forward proxy.ContextDialer
	config  *Config

	/* Auth from the url.  Avoids a function call */
	haveAuth bool
	username string
	password string
}

var (
	_ proxy.Dialer        = (*connectDialer)(nil)
	_ proxy.ContextDialer = (*connectDialer)(nil)
)

// NewWithConfig is like New, but allows control over various options.
func NewWithConfig(u *url.URL, forward proxy.ContextDialer, config *Config) (proxy.ContextDialer, error) {
	/* Make sure we have an allowable scheme */
	if "http" != u.Scheme && "https" != u.Scheme {
		return nil, ErrorUnsupportedScheme(errors.New(
			"connectproxy: unsupported scheme " + u.Scheme,
		))
	}

	/* Need at least an empty config */
	if nil == config {
		config = &Config{}
	}

	/* To be returned */
	cd := &connectDialer{
		u:       u,
		forward: forward,
		config:  config,
	}

	/* Work out the TLS server name */
	if "" == cd.config.ServerName {
		h, _, err := net.SplitHostPort(u.Host)
		if nil != err && "missing port in address" == err.Error() {
			h = u.Host
		}
		cd.config.ServerName = h
	}

	/* Parse out auth */
	/* Below taken from https://gist.github.com/jim3ma/3750675f141669ac4702bc9deaf31c6b */
	if nil != u.User {
		cd.haveAuth = true
		cd.username = u.User.Username()
		cd.password, _ = u.User.Password()
	}

	return cd, nil
}

// Dial connects to the given address via the server.
func (cd *connectDialer) Dial(network, addr string) (net.Conn, error) {
	return cd.DialContext(context.Background(), network, addr)
}

// DialContext connects to the given address via the server with context
func (cd *connectDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	if cd.config.DialTimeout != 0 {
		var cancelF func()
		ctx, cancelF = context.WithDeadline(ctx, time.Now().Add(cd.config.DialTimeout))
		defer cancelF()
	}

	/* Connect to proxy server */
	nc, err := cd.forward.DialContext(ctx, "tcp", cd.u.Host)
	if nil != err {
		return nil, err
	}
	defer nc.Close()

	/* Upgrade to TLS if necessary */
	if "https" == cd.u.Scheme {
		nc = tls.Client(nc, &tls.Config{
			InsecureSkipVerify: cd.config.InsecureSkipVerify,
			ServerName:         cd.config.ServerName,
		})
	}

	/* The below adapted from https://gist.github.com/jim3ma/3750675f141669ac4702bc9deaf31c6b */

	/* Work out the URL to request */
	// HACK. http.ReadRequest also does this.
	reqURL, err := url.Parse("http://" + addr)
	if err != nil {
		return nil, err
	}
	reqURL.Scheme = ""
	req, err := http.NewRequest(http.MethodConnect, reqURL.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Close = false

	if len(cd.config.Header) > 0 {
		req.Header = cd.config.Header
	}

	if cd.haveAuth {
		basicAuth := "Basic " + base64.StdEncoding.EncodeToString([]byte(cd.username+":"+cd.password))
		req.Header.Add("Proxy-Authorization", basicAuth)
	}

	/* Send the request */
	err = req.Write(nc)
	if err != nil {
		return nil, err
	}

	/* Timer to terminate long reads */
	var connected = make(chan string)
	go func() {
		select {
		case <-ctx.Done():
		case <-connected:
		}
	}()

	/* Wait for a response */
	resp, err := http.ReadResponse(bufio.NewReader(nc), req)
	close(connected)
	if nil != resp {
		resp.Body.Close()
	}
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			return nil, ErrorConnectionTimeout(fmt.Errorf(
				"connectproxy: no connection to %q after context deadline exceeded",
				reqURL,
			))
		}
		return nil, err
	}

	/* Make sure we can proceed */
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf(
			"connectproxy: non-OK status: %v",
			resp.Status,
		)
	}

	return nc, nil
}
