/**
* @Author: kiosk
* @Mail: weijiaxiang007@foxmail.com
* @Date: 2021/1/1
**/
package packet

import (
	"bufio"
	"fmt"
	"github.com/google/gopacket"
	"io"
	"sync"
	"github.com/kiosk404/tls-decrypt/tls"
	"github.com/kiosk404/tls-decrypt/utils"
)

/*
 * HTTP part
 */

type TLSReader struct {
	ident    string
	isClient bool
	bytes    chan []byte
	data     []byte
	hexdump  bool
	parent   *TcpStream
	tls 	 *mytls.TLSStream
}

func NewTLSReader(parent *TcpStream, netFlow,transport gopacket.Flow, isClient,hexdump bool, tls *mytls.TLSStream) TLSReader {
	return TLSReader{
		ident:    fmt.Sprintf("%s %s", netFlow, transport),
		isClient: isClient,
		bytes:    make(chan []byte),
		data:     nil,
		hexdump:  hexdump,
		parent:   parent,
		tls:	  tls,
	}
}

func (t *TLSReader) Read(p []byte) (int, error) {
	ok := true
	for ok && len(t.data) == 0 {
		t.data, ok = <-t.bytes
	}
	if !ok || len(t.data) == 0 {
		return 0, io.EOF
	}

	l := copy(p, t.data)
	t.data = t.data[l:]
	return l, nil
}


func (t *TLSReader) run(wg *sync.WaitGroup) {
	defer wg.Done()
	b := bufio.NewReader(t)

	for true {
		if t.isClient {
			// Request
			buf := make([]byte, 1024)
			n, err := b.Read(buf)
			if err != nil {
				utils.Logging.Error().Err(err)
			}

			plaintext,err := t.tls.TLSDecrypt(buf[:n])
			if err != nil {
				utils.Logging.Error().Err(err).Msg("decrypt error")
			}
			fmt.Printf("%s %s \n",t.ident, plaintext)
		} else {
			// Response
			buf := make([]byte, 1024)
			n, err := b.Read(buf)
			if err != nil {
				utils.Logging.Error().Err(err)
			}

			plaintext,err := t.tls.TLSDecrypt(buf[:n])
			if err != nil {
				utils.Logging.Error().Err(err).Msg("decrypt error")
			}
			fmt.Printf("%s %s \n",t.ident, plaintext)
		}
	}
}