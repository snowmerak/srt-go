package server

import (
	"context"
	"fmt"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"net"
	"sync"
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

func (s *Server) Listen(ctx context.Context) error {
	listenUDP, err := net.ListenUDP("udp", s.udpAddr)
	if err != nil {
		return fmt.Errorf("failed to listen: %w", err)
	}

	context.AfterFunc(ctx, func() {
		if err := listenUDP.Close(); err != nil {
			s.logger.Error().Err(err).Msg("failed to close")
		}

		s.udpConn.Close()
		s.logger.Info().Msg("server closed")
	})

	s.udpConn = listenUDP

	return nil
}

const maxBufferSize = 1500

var bufferPool = sync.Pool{
	New: func() interface{} {
		return make([]byte, maxBufferSize)
	},
}

func getBufferFromPool() []byte {
	return bufferPool.Get().([]byte)
}

func triggerPuttingBufferToPool(buf []byte) func() {
	return func() {
		putBufferToPool(buf)
	}
}

func putBufferToPool(buf []byte) {
	bufferPool.Put(buf)
}

func (s *Server) Serve(ctx context.Context, callback func(net.PacketConn, net.Addr, []byte, func())) error {
	done := ctx.Done()
	for {
		select {
		case <-done:
			return nil
		default:
			buf := getBufferFromPool()

			log.Info().Msg("waiting for data")
			n, addr, err := s.udpConn.ReadFromUDP(buf)
			if err != nil {
				log.Error().Err(err).Msg("failed to read from udp")
				return err
			}

			callback(s.udpConn, addr, buf[:n], triggerPuttingBufferToPool(buf))

			s.logger.Info().Msgf("received %d bytes from %s", n, addr)
		}
	}
}
