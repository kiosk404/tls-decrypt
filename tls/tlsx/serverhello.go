/**
* @Author: kiosk
* @Mail: weijiaxiang007@foxmail.com
* @Date: 2020/12/27
**/
package tlsx

import (
	"encoding/hex"
	"fmt"
)

const (
	ServerHelloRandomLen = 32
)

type ServerHello struct {
	TLSMessage
	HandshakeType    uint8
	HandshakeLen     uint32
	HandshakeVersion Version
	Random           []byte
	SessionIDLen     uint32
	SessionID        []byte
	CipherSuites     CipherSuite
	CompressMethods  uint8
	ExtensionLen     uint16
	Extensions       map[Extension]uint16 // [Type]Length
}

func (ch ServerHello) String() string {
	str := fmt.Sprintln("Version:", ch.Version)
	str += fmt.Sprintln("Handshake Type:", ch.HandshakeType)
	str += fmt.Sprintln("Handshake Version:", ch.HandshakeVersion)
	str += fmt.Sprintf("Cipher Suites %v\n", ch.CipherSuites)
	str += fmt.Sprintf("SessionID: %#v\n", ch.SessionID)
	str += fmt.Sprintln("Random: ", hex.EncodeToString(ch.Random))
	return str
}

func (ch ServerHello) GetTLSCipherSuite() uint16 {
	return uint16(ch.CipherSuites)
}

func (ch ServerHello) GetTLSVersion() uint16 {
	return uint16(ch.Version)
}

func (ch *ServerHello) Unmarshall(payload []byte) error {
	ch.Raw = payload
	ch.Type = uint8(payload[0])
	ch.Version = Version(payload[1])<<8 | Version(payload[2])
	ch.MessageLen = uint16(payload[3])<<8 | uint16(payload[4])

	if ch.Type != uint8(22) {
		return ErrHandshakeWrongType
	}

	hs := payload[5:]

	if len(hs) < 6 {
		return ErrHandshakeBadLength
	}

	ch.HandshakeType = uint8(hs[0])

	if ch.HandshakeType != 2 {
		return ErrHandshakeWrongType
	}
	ch.HandshakeLen = uint32(hs[1])<<16 | uint32(hs[2])<<8 | uint32(hs[3])
	ch.HandshakeVersion = Version(hs[4])<<8 | Version(hs[5])

	hs = hs[6:]

	if len(hs) < ServerHelloRandomLen {
		return ErrHandshakeBadLength
	}

	// Get random data
	ch.Random = hs[:ServerHelloRandomLen]

	hs = hs[ServerHelloRandomLen:]

	if len(hs) < 1 {
		return ErrHandshakeBadLength
	}

	// Get SessionID
	ch.SessionIDLen = uint32(hs[0])
	hs = hs[1:]

	if len(hs) < int(ch.SessionIDLen) {
		return ErrHandshakeBadLength
	}

	if ch.SessionIDLen != 0 {
		ch.SessionID = hs[:ch.SessionIDLen]
	}

	hs = hs[ch.SessionIDLen:]

	if len(hs) < 2 {
		return ErrHandshakeBadLength
	}

	// Cipher Suite

	//cipherSuite,_ := strconv.ParseUint(hex.EncodeToString(hs[:2]),16,32)
	ch.CipherSuites = CipherSuite(hs[0])<<8 | CipherSuite(hs[1])
	hs = hs[2:]

	if len(hs) < 2 {
		return ErrHandshakeBadLength
	}

	// CompressMethods
	ch.CompressMethods = uint8(hs[0])

	hs = hs[1:]

	if len(hs) < 2 {
		return ErrHandshakeBadLength
	}

	// Extension
	ch.ExtensionLen = uint16(hs[0])<<8 | uint16(hs[1])

	if len(hs) < int(ch.ExtensionLen) {
		return ErrHandshakeExtBadLength
	}
	return nil
}