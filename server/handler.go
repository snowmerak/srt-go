package server

import (
	"fmt"
	"github.com/rs/zerolog/log"
	"net"
)

type srtPacket struct {
	Flag      bool
	Header    []byte
	Timestamp uint32
	SocketId  uint32
	Data      []byte
}

func parseSrtPacket(packet []byte) (*srtPacket, error) {
	if len(packet) < 20 {
		return nil, fmt.Errorf("invalid packet length")
	}

	flag := packet[0]>>7 == 1

	return &srtPacket{
		Flag:      flag,
		Header:    packet[:8],
		Timestamp: uint32(packet[8])<<24 | uint32(packet[9])<<16 | uint32(packet[10])<<8 | uint32(packet[11]),
		SocketId:  uint32(packet[12])<<24 | uint32(packet[13])<<16 | uint32(packet[14])<<8 | uint32(packet[15]),
		Data:      packet[16:],
	}, nil
}

func DefaultCallback(conn net.PacketConn, addr net.Addr, buf []byte, putBuffer func()) {
	defer putBuffer()

	log.Info().Msgf("received %d bytes from %s", len(buf), addr)
	parsed, err := parseSrtPacket(buf)
	if err != nil {
		log.Error().Err(err).Msg("failed to parse packet")
		return
	}

	log.Info().Interface("parsed", parsed).Msgf("parsed packet")
}
