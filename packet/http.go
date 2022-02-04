/**
* @Author: kiosk
* @Mail: weijiaxiang007@foxmail.com
* @Date: 2020/12/27
**/
package packet

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"encoding/hex"
	"fmt"
	"github.com/google/gopacket"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"path"
	"sync"
	"github.com/kiosk404/tls-decrypt/utils"
)

/*
 * HTTP part
 */

type HttpReader struct {
	ident    string
	isClient bool
	bytes    chan []byte
	data     []byte
	hexdump  bool
	parent   *TcpStream
}


func NewHTTPReader(parent *TcpStream,netFlow,transport gopacket.Flow, isClient,hexdump bool) HttpReader {
	return HttpReader{
		ident:    fmt.Sprintf("%s %s", netFlow, transport),
		isClient: isClient,
		bytes:    make(chan []byte),
		data:     nil,
		hexdump:  hexdump,
		parent:   parent,
	}
}

func (h *HttpReader) Read(p []byte) (int, error) {
	ok := true
	for ok && len(h.data) == 0 {
		h.data, ok = <-h.bytes
	}
	if !ok || len(h.data) == 0 {
		return 0, io.EOF
	}

	l := copy(p, h.data)
	h.data = h.data[l:]
	return l, nil
}

func (h *HttpReader) run(wg *sync.WaitGroup) {
	defer wg.Done()
	b := bufio.NewReader(h)

	for true {
		if h.isClient {
			req, err := http.ReadRequest(b)
			if err == io.EOF || err == io.ErrUnexpectedEOF {
				break
			} else if err != nil {
				utils.Logging.Error().Str("HTTP Request error", err.Error()).Msg("HTTP-request")
				continue
			}
			body, err := ioutil.ReadAll(req.Body)
			if err != nil {
				utils.Logging.Error().Str("Got body err", err.Error()).Msg("HTTP-request-body")
			} else if h.hexdump {
				utils.Logging.Info().Str("Body Hex", hex.Dump(body)).Int("Body Len", len(body))
			}
			_ = req.Body.Close()
			utils.Logging.Info().Str("HTTP ident", h.ident).Str("Method", req.Method).Str("URL", req.URL.String())

			h.parent.Lock()
			h.parent.urls = append(h.parent.urls, req.URL.String())
			h.parent.Unlock()
		} else {
			res, err := http.ReadResponse(b, nil)
			var req string
			h.parent.Lock()
			if len(h.parent.urls) == 0 {
				req = fmt.Sprintf("<no-request-seen>")
			} else {
				req, h.parent.urls = h.parent.urls[0], h.parent.urls[1:]
			}
			h.parent.Unlock()
			if err == io.EOF || err == io.ErrUnexpectedEOF {
				break
			} else if err != nil {
				utils.Logging.Error().Str("Http Ident", h.ident).Err(err).Msg("HTTP-response")
				continue
			}
			body, err := ioutil.ReadAll(res.Body)
			s := len(body)
			if err != nil {
				utils.Logging.Error().Str("HTTP Ident",h.ident).Int("failed to get body (parsed len)", s).Err(err).Msg("HTTP-response-body")
			}
			if h.hexdump {
				utils.Logging.Info().Str("Body Hex", hex.Dump(body)).Int("Body Len", len(body))
			}
			_ = res.Body.Close()
			sym := ","
			if res.ContentLength > 0 && res.ContentLength != int64(s) {
				sym = "!="
			}
			contentType, ok := res.Header["Content-Type"]
			if !ok {
				contentType = []string{http.DetectContentType(body)}
			}
			encoding := res.Header["Content-Encoding"]

			utils.Logging.Info().Str("Ident", h.ident).Str("Status", res.Status).Str("URL", req).Int64("ContentLength", res.ContentLength).Str("ContentType", contentType[0]).Str("encoding", encoding[0]).Str("sym", sym).Msg("HTTP Response")

			if err == nil {
				base := url.QueryEscape(path.Base(req))
				base = "incomplete-" + base

				target := base
				n := 0
				for true {
					_, err := os.Stat(target)
					//if os.IsNotExist(err) != nil {
					if err != nil {
						break
					}
					target = fmt.Sprintf("%s-%d", base, n)
					n++
				}
				f, err := os.Create(target)
				if err != nil {
					utils.Logging.Error().Str("Cannot create ", target).Err(err).Msg("HTTP-create")
					continue
				}
				var r io.Reader
				r = bytes.NewBuffer(body)
				if len(encoding) > 0 && (encoding[0] == "gzip" || encoding[0] == "deflate") {
					r, err = gzip.NewReader(r)
					if err != nil {
						utils.Logging.Error().Str("Failed to gzip decode", err.Error()).Msg("HTTP-gunzip")
					}
				}
				if err == nil {
					w, err := io.Copy(f, r)
					if _, ok := r.(*gzip.Reader); ok {
						_ = r.(*gzip.Reader).Close()
					}
					_ = f.Close()
					if err != nil {
						utils.Logging.Error().Str("failed to save ", h.ident).Str("target",target).Err(err).Msg("HTTP-save")
					} else {
						utils.Logging.Info().Str("Ident",h.ident).Str("target", target).Int64("Len", w).Msg("Saved")
					}
				}
			}
		}
	}
}


