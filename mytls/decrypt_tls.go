package mytls

import (
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"strings"
)

func GetMasterFromPreMasterSecret(version uint16,cipherSuite uint16,preMasterSecret, clientRandom, serverRandom []byte) []byte {
	suiteCipher := cipherSuiteByID(cipherSuite)
	masterSecret := masterFromPreMasterSecret(version,
		suiteCipher,preMasterSecret,
		clientRandom,serverRandom)
	return masterSecret
}

func GetMaster(c string) (client_random, pre_master string ){
	fileName := "/Users/weijiaxiang/GoProject/src/netAnalyzer/pcap/sslkeylog.log"
	contentByte,err := ioutil.ReadFile(fileName)
	if err != nil {
		return "",""
	}
	contentMain := strings.Split(string(contentByte),"\n")
	for _,v := range contentMain {
		master := strings.Split(v," ")
		if len(master) == 3 {
			c_type := master[0]
			c_random := master[1]
			pre := master[2]

			if c_type == "CLIENT_RANDOM" && c_random == c{
				return c_random,pre
			}
		}

	}
	return "", ""
}



func TLSDecrypt(record []byte,version,cipherSuite uint16,clientRandom,serverRandom []byte,seq [8]byte) {
	suite := cipherSuiteByID(cipherSuite)
	_,master := GetMaster(hex.EncodeToString(clientRandom))
	byteMaster,_ := hex.DecodeString(master)
	cCipher,_,cHash,_,err := establishKeys(version,suite,byteMaster,clientRandom,serverRandom)

	if err != nil {
		fmt.Println("establishKeys Error :",err)
	}

	var clientConn = halfConn{
		err:nil,
		version:VersionTLS12,
		cipher:cCipher,
		mac:cHash,
		seq:seq,
	}

	plaintext,_,err := clientConn.decrypt(record)
	if err != nil {
		fmt.Println("error !!!!",err.Error())
	}else {
		fmt.Println(string(plaintext))
	}
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