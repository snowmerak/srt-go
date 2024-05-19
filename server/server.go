package server

import (
	"context"
	"github.com/rs/zerolog"
	"net"
)

type Option func(*Server)

func WithLogger(logger *zerolog.Logger) Option {
	return func(s *Server) {
		s.logger = logger
	}
}

func WithAddress(address string) Option {
	return func(s *Server) {
		udpAddr, err := net.ResolveUDPAddr("udp", address)
		if err != nil {
			s.logger.Error().Err(err).Msg("failed to resolve address")
			return
		}

		s.udpAddr = udpAddr
	}
}

type Server struct {
	udpConn *net.UDPConn
	udpAddr *net.UDPAddr
	logger  *zerolog.Logger
}

func New(ctx context.Context, opt ...Option) *Server {
	s := &Server{}
	for _, o := range opt {
		o(s)
	}

	return s
}
