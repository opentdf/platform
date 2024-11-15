package realip

import (
	"context"
	"net/http"
	"testing"

	"connectrpc.com/connect"
	"github.com/stretchr/testify/suite"
)

type RealIPTestSuite struct {
	suite.Suite
}

func TestRealIPSuite(t *testing.T) {
	suite.Run(t, new(RealIPTestSuite))
}

func (s *RealIPTestSuite) Test_getIP_from_x_real_ip_header() {
	ip := "1.1.1.1"
	peer := connect.Peer{}

	headers := http.Header{}
	headers.Add(XRealIP, ip)
	foundIP := getIP(context.Background(), peer, headers)
	s.Equal(ip, foundIP.String())
}

func (s *RealIPTestSuite) Test_getIP_from_x_forwarded_for_header() {
	ip := "1.1.1.1"
	peer := connect.Peer{}

	headers := http.Header{}
	headers.Add(XForwardedFor, ip)
	foundIP := getIP(context.Background(), peer, headers)
	s.Equal(ip, foundIP.String())
}

func (s *RealIPTestSuite) Test_getIP_from_true_client_ip_header() {
	ip := "1.1.1.1"
	peer := connect.Peer{}

	headers := http.Header{}
	headers.Add(TrueClientIP, ip)
	foundIP := getIP(context.Background(), peer, headers)
	s.Equal(ip, foundIP.String())
}

func (s *RealIPTestSuite) Test_getIP_from_peer() {
	ip := "1.1.1.1"
	peer := connect.Peer{Addr: ip + ":1234"}

	headers := http.Header{}
	foundIP := getIP(context.Background(), peer, headers)
	s.Equal(ip, foundIP.String())
}
