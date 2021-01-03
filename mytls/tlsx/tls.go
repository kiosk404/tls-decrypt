/**
* @Author: kiosk
* @Mail: weijiaxiang007@foxmail.com
* @Date: 2020/12/28
**/
package tlsx

import "errors"

const (
	SNINameTypeDNS 		uint8 = 0
	OCSPStatusRequest 	uint8 = 1
)

var (
	ErrHandshakeWrongType    = errors.New("handshake is of wrong type, or not a handshake message")
	ErrHandshakeBadLength    = errors.New("handshake has a malformed length")
	ErrHandshakeExtBadLength = errors.New("handshake extension has a malformed length")
)

var (
	TLSHandShake = uint8(22)
	TLSApplication = uint8(23)
)


type TLSMessage struct {
	Raw        []byte
	Type       uint8
	Version    Version
	MessageLen uint16
}


