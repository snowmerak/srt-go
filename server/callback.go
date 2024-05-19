package server

import (
	"github.com/rs/zerolog/log"
	"net"
)

func DefaultCallback(conn net.PacketConn, addr net.Addr, buf []byte, putBuffer func()) {
	defer putBuffer()

	log.Debug().Msgf("received %d bytes from %s", len(buf), addr)
	parsed, err := parseSrtPacket(buf)
	if err != nil {
		log.Error().Err(err).Msg("failed to parse packet")
		return
	}

	log.Info().Interface("parsed", parsed).Msgf("parsed packet")

	switch parsed.Flag {

	}
}
