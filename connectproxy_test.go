package connectproxy

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"testing"

	"golang.org/x/net/proxy"
)

// TODO: write more tests

func noError(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Errorf("got error: %+v", err)
	}
}

func Test_connectDialer_DialContext(t *testing.T) {
	targetHandles := 0
	targetHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		targetHandles++
		w.WriteHeader(200)
	})
	targetTestServer := httptest.NewServer(targetHandler)
	defer targetTestServer.Close()

	targetURL, err := url.Parse(targetTestServer.URL)
	noError(t, err)

	proxyTestServer := httptest.NewServer(httputil.NewSingleHostReverseProxy(targetURL))
	defer proxyTestServer.Close()

	proxyURL, err := url.Parse(proxyTestServer.URL)
	noError(t, err)

	cd, err := NewWithConfig(proxyURL, &net.Dialer{}, nil)
	noError(t, err)

	cli := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return cd.DialContext(ctx, network, addr)
			},
		},
	}
	_, err = cli.Get(targetTestServer.URL + "/foo")
	noError(t, err)

	if targetHandles != 2 {
		t.Errorf("target server want to 2 requests but got %d", targetHandles)
	}
}

func TestRegister(t *testing.T) {
	Register(&Config{})

	urls := []string{
		"http://localhost:7890",
		"https://localhost:7890",
		"socks5://localhost:7890",
	}

	for _, u := range urls {
		u, err := url.Parse(u)
		noError(t, err)

		_, err = proxy.FromURL(u, proxy.Direct)
		noError(t, err)
	}
}
