package server

import (
	"fmt"
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

/*
0                   1                   2                   3

	0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1

+-+-+-+-+-+-+-+-+-+-+-+-+- SRT Header +-+-+-+-+-+-+-+-+-+-+-+-+-+
|0|                    Packet Sequence Number                   |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|P P|O|K K|R|                   Message Number                  |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                           Timestamp                           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                  Destination SRT Socket ID                    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
+                            Payload                            +
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                       Authentication Tag                      |
|                        (GCM: 16 bytes)                        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/
type dataPacket struct {
	PacketSequenceNumber    uint32
	PacketPositionFlag      uint8
	OrderFlag               bool
	KeyBasedEncryptionFlag  uint8
	RetransmittedPacketFlag bool
	MessageNumber           uint32
	Timestamp               uint32
	DestinationSocketId     uint32
	Payload                 []byte
	AuthenticationTag       []byte
}

func convertToDataPacket(packet *srtPacket, hasAuthenticationTag bool) (*dataPacket, error) {
	dp := &dataPacket{}
	dp.PacketSequenceNumber = uint32(packet.Header[0])<<24 | uint32(packet.Header[1])<<16 | uint32(packet.Header[2])<<8 | uint32(packet.Header[3])
	dp.PacketPositionFlag = packet.Header[4] >> 6
	dp.OrderFlag = packet.Header[4]>>5&1 == 1
	dp.KeyBasedEncryptionFlag = packet.Header[4] >> 3 & 3
	dp.RetransmittedPacketFlag = packet.Header[4]>>2&1 == 1
	dp.MessageNumber = uint32(packet.Header[4]&3)<<24 | uint32(packet.Header[5])<<16 | uint32(packet.Header[6])<<8 | uint32(packet.Header[7])
	dp.Timestamp = packet.Timestamp
	dp.DestinationSocketId = packet.SocketId
	dp.Payload = packet.Data
	if hasAuthenticationTag {
		dp.AuthenticationTag = packet.Data[len(packet.Data)-16:]
		dp.Payload = packet.Data[:len(packet.Data)-16]
	}

	return dp, nil
}

/*
	0                   1                   2                   3
	0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1

+-+-+-+-+-+-+-+-+-+-+-+-+- SRT Header +-+-+-+-+-+-+-+-+-+-+-+-+-+
|1|         Control Type        |            Subtype            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                   Type-specific Information                   |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                           Timestamp                           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                  Destination SRT Socket ID                    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+- CIF -+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
+                   Control Information Field                   +
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/
type controlPacket struct {
	ControlType             uint16
	Subtype                 uint16
	TypeSpecificInformation uint32
	Timestamp               uint32
	DestinationSocketId     uint32
	ControlInformationField []byte
}

func convertToControlPacket(packet *srtPacket) (*controlPacket, error) {
	cp := &controlPacket{}
	cp.ControlType = uint16(packet.Header[0]&0b01111111)<<8 | uint16(packet.Header[1])
	cp.Subtype = uint16(packet.Header[2])<<8 | uint16(packet.Header[3])
	cp.TypeSpecificInformation = uint32(packet.Header[4])<<24 | uint32(packet.Header[5])<<16 | uint32(packet.Header[6])<<8 | uint32(packet.Header[7])
	cp.Timestamp = packet.Timestamp
	cp.DestinationSocketId = packet.SocketId
	cp.ControlInformationField = packet.Data

	return cp, nil
}

const (
	PacketTypeHandshake         = 0x0000
	PacketTypeKeepAlive         = 0x0001
	PacketTypeAck               = 0x0002
	PacketTypeNak               = 0x0003
	PacketTypeCongestionWarning = 0x0004
	PacketTypeShutdown          = 0x0005
	PacketTypeAckAck            = 0x0006
	PacketTypeDropReq           = 0x0007
	PacketTypePeerError         = 0x0008
	PacketTypeUserDefined       = 0x7FFF
)

/*
	0                   1                   2                   3
	0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1

+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                          HS Version                           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|        Encryption Field       |        Extension Field        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|0|               Initial Packet Sequence Number                |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                 Maximum Transmission Unit Size                |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Maximum Flow Window Size                   |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                         Handshake Type                        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                         SRT Socket ID                         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                           SYN Cookie                          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
+                                                               +
|                                                               |
+                        Peer IP Address                        +
|                                                               |
+                                                               +
|                                                               |
+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
|         Extension Type        |        Extension Length       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
+                       Extension Contents                      +
|                                                               |
+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
*/
type handshakeControlPacket struct {
	HandshakeVersion            uint32
	EncryptionField             uint16
	ExtensionField              uint16
	InitialPacketSequenceNumber uint32
	MaximumTransmissionUnitSize uint32
	MaximumFlowWindowSize       uint32
	HandshakeType               uint32
	SRTSocketId                 uint32
	SYNCookie                   uint32
	PeerIPAddress               []byte
	ExtensionType               uint16
	ExtensionLength             uint16
	ExtensionContents           []byte
}

const (
	HandshakeTypeDone       = 0xFFFFFFFD
	HandshakeTypeAgreement  = 0xFFFFFFFE
	HandshakeTypeConclusion = 0xFFFFFFFF
	HandshakeTypeWaveahand  = 0x00000000
	HandshakeTypeInduction  = 0x00000001
)

func convertToHandshakeControlPacket(data []byte) (*handshakeControlPacket, error) {
	hcp := &handshakeControlPacket{}

	hcp.HandshakeVersion = uint32(data[0])<<24 | uint32(data[1])<<16 | uint32(data[2])<<8 | uint32(data[3])
	hcp.EncryptionField = uint16(data[4])<<8 | uint16(data[5])
	hcp.ExtensionField = uint16(data[6])<<8 | uint16(data[7])
	hcp.InitialPacketSequenceNumber = uint32(data[8])<<24 | uint32(data[9])<<16 | uint32(data[10])<<8 | uint32(data[11])
	hcp.MaximumTransmissionUnitSize = uint32(data[12])<<24 | uint32(data[13])<<16 | uint32(data[14])<<8 | uint32(data[15])
	hcp.MaximumFlowWindowSize = uint32(data[16])<<24 | uint32(data[17])<<16 | uint32(data[18])<<8 | uint32(data[19])
	hcp.HandshakeType = uint32(data[20])<<24 | uint32(data[21])<<16 | uint32(data[22])<<8 | uint32(data[23])
	hcp.SRTSocketId = uint32(data[24])<<24 | uint32(data[25])<<16 | uint32(data[26])<<8 | uint32(data[27])
	hcp.SYNCookie = uint32(data[28])<<24 | uint32(data[29])<<16 | uint32(data[30])<<8 | uint32(data[31])
	hcp.PeerIPAddress = data[32:48]
	hcp.ExtensionType = uint16(data[48])<<8 | uint16(data[49])
	hcp.ExtensionLength = uint16(data[50])<<8 | uint16(data[51])
	hcp.ExtensionContents = data[52:]

	return hcp, nil
}
