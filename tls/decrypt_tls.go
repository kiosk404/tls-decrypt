package tls

import (
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/kiosk404/tls-decrypt/tls/tlsx"
	"github.com/kiosk404/tls-decrypt/utils"
	"io/ioutil"
	"strings"
)

var sslKeyContent []byte

type TLSDirection uint8

const (
	ClientHello  TLSDirection = 0
	ServerHello  TLSDirection = 1
)

func SetKeyLogContent(sslKeyFile string) {
	var err error

	sslKeyContent,err = ioutil.ReadFile(sslKeyFile)
	if err != nil {
		utils.Logging.Fatal().Err(err).Msgf("Can't Open SSLKeyFile %s", sslKeyFile)
	}
}

type TLSStream struct {
	KeyLabel  		string
	Version 		uint16
	CipherSuite 	uint16
	ClientRandom 	[]byte
	ServerRandom 	[]byte
	MasterKey 		[]byte
	Seq 			[8]byte
	Conn 			halfConn
}

func NewTLSStream() *TLSStream {
	tlsStream := &TLSStream{
		Seq: [8]byte{0,0,0,0,0,0,0,1},
	}

	return tlsStream
}

func (t *TLSStream) ShowHandShakeResult() {
	fmt.Printf("KeyLabel: %s \n", t.KeyLabel)
	fmt.Printf("Version: %x \n",t.Version)
	fmt.Printf("CipherSuite: %x \n", t.CipherSuite)
	fmt.Printf("ClientRandom: %s \n", hex.EncodeToString(t.ClientRandom))
	fmt.Printf("ServerRandom: %s \n", hex.EncodeToString(t.ServerRandom))
	fmt.Printf("Master Key: %s \n", hex.EncodeToString(t.MasterKey))
}

// See https://developer.mozilla.org/en-US/docs/Mozilla/Projects/NSS/Key_Log_Format
//
func (t *TLSStream) GetMasterKey(clientRandom string) {
	contentMain := strings.Split(string(sslKeyContent),"\n")
	for _,v := range contentMain {
		seriesLine := strings.Split(v," ")
		if len(seriesLine) == 3 {
			cType, cRandom, Secret := seriesLine[0], seriesLine[1], seriesLine[2]

			if cType == "CLIENT_RANDOM" && cRandom == clientRandom {
				t.KeyLabel = cType
				t.MasterKey,_ = hex.DecodeString(Secret)
			}
		}
	}
}

func (t *TLSStream) TLSDecrypt(record []byte) (string, error) {
	plaintext,_, err := t.Conn.decrypt(record)

	if err != nil {
		return "", err
	}

	t.incSeq()

	return string(plaintext), nil
}


func (t *TLSStream) EstablishConn() error {
	if t.Version == 0 || t.MasterKey == nil || t.ClientRandom == nil || t.ServerRandom == nil ||t.CipherSuite == 0 {
		return errors.New("missing decrypt parameter")
	}

	// Only Need Client Cipher and Client Hash
	cCipher,_,cHash,_,err := establishKeys(t.Version, cipherSuiteByID(t.CipherSuite), t.MasterKey, t.ClientRandom, t.ServerRandom)
	if err != nil {
		utils.Logging.Error().Err(err).Msg("Establish keys error")
		return err
	}

	var clientConn = halfConn{
		version:	t.Version,
		cipher:		cCipher,
		mac:		cHash,
		seq:		t.Seq,
	}

	t.Conn = clientConn
	return nil
}

func establishKeys(version uint16,suite *cipherSuite, masterSecret,clientRandom,serverRandom []byte)  ( cCipher,sCipher interface{},cHash,sHash macFunction, err error) {
	clientMAC, serverMAC, clientKey, serverKey, clientIV, serverIV :=
		keysFromMasterSecret(version, suite, masterSecret, clientRandom, serverRandom, suite.macLen, suite.keyLen, suite.ivLen)

	var clientCipher, serverCipher interface{}
	var clientHash, serverHash macFunction
	if suite.cipher != nil {
		clientCipher = suite.cipher(clientKey, clientIV, false /* not for reading */)
		clientHash = suite.mac(version, clientMAC)
		serverCipher = suite.cipher(serverKey, serverIV, true /* for reading */)
		serverHash = suite.mac(version, serverMAC)
	} else {
		clientCipher = suite.aead(clientKey, clientIV)
		serverCipher = suite.aead(serverKey, serverIV)
	}

	return clientCipher,serverCipher,clientHash,serverHash,nil
}


func (t *TLSStream)UnmarshalHandshake(record []byte, dir TLSDirection) error {
	switch dir {
	case ClientHello:
		var hello = tlsx.ClientHello{}
		err := hello.Unmarshall(record)

		switch err {
		case nil:
			t.ClientRandom = hello.Random
		case tlsx.ErrHandshakeExtBadLength:
			return errors.New("inner error: " + err.Error())
		case tlsx.ErrHandshakeBadLength:
			return errors.New("inner error: " + err.Error())
		default:
			// pass
		}

	case ServerHello:
		var hello = tlsx.ServerHello{}
		err := hello.Unmarshall(record)

		switch err {
		case nil:
			t.ServerRandom = hello.Random
			t.Version = hello.GetTLSVersion()
			t.CipherSuite = hello.GetTLSCipherSuite()
			t.GetMasterKey(hex.EncodeToString(t.ClientRandom))
		case tlsx.ErrHandshakeExtBadLength:
			return errors.New("inner error: " + err.Error())
		case tlsx.ErrHandshakeBadLength:
			return errors.New("inner error: " + err.Error())
		default:
			// pass
		}
	}

	return nil
}


// incSeq increments the sequence number.
func (t *TLSStream) incSeq() {
	for i := 7; i >= 0; i-- {
		t.Seq[i]++
		if t.Seq[i] != 0 {
			return
		}
	}
}