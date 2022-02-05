/**
* @Author: kiosk
* @Mail: weijiaxiang007@foxmail.com
* @Date: 2020/12/27
**/
package main

import (
	"flag"
	"github.com/kiosk404/tls-decrypt/packet"
	"github.com/kiosk404/tls-decrypt/utils"
)

var maxcount = flag.Int("c", -1, "Only grab this many packets, then exit")
var decoder = flag.String("decoder", "", "Name of the decoder to use (default: guess from capture)")
var lazy = flag.Bool("lazy", false, "If true, do lazy decoding")
var nodefrag = flag.Bool("nodefrag", false, "If true, do not do IPv4 defrag")
var checksum = flag.Bool("checksum", false, "Check TCP checksum")
var nooptcheck = flag.Bool("nooptcheck", false, "Do not check TCP options (useful to ignore MSS on captures with TSO)")
var ignorefsmerr = flag.Bool("ignorefsmerr", false, "Ignore TCP FSM errorsCnt")
var verbose = flag.Bool("verbose", false, "Be verbose")
var quiet = flag.Bool("quiet", false, "Be quiet regarding errorsCnt")

// http
var nohttp = flag.Bool("nohttp", false, "Disable HTTP parsing")
var output = flag.String("output", "", "Path to create file for HTTP 200 OK responses")
var hexdump = flag.Bool("dump", false, "Dump HTTP request/response as hex")
var hexdumppkt = flag.Bool("dumppkt", false, "Dump packet as hex")

// capture
var iface = flag.String("i", "eth0", "Interface to read packets from")
var fname = flag.String("r", "", "Filename to read from, overrides -i")
var snaplen = flag.Int("s", 65536, "Snap length (number of bytes max to read per packet")
var promisc = flag.Bool("promisc", true, "Set promiscuous mode")

// tls_decrypt
var decrypt = flag.Int("decrypt", 0, "TLS Decrypt Port")
var sslkeylog = flag.String("sslkeylog","","TLS keylog file to decrypt")


func SetLogLevel() {
	// 设置输出级别
	if *verbose {
		utils.SetDebugLevel()
	} else if *quiet {
		utils.SetQuietLevel()
	}
}

func SetCommandLine() utils.Command {
	return utils.Command{
		Maxcount: 		*maxcount,
		Decoder:  		*decoder,
		Lazy:			*lazy,
		Nodefrag: 		*nodefrag,
		Checksum:		*checksum,
		Nooptcheck: 	*nooptcheck,
		Ignorefsmerr: 	*ignorefsmerr,
		Verbose: 		*verbose,
		Quiet: 			*quiet,
		Nohttp:			*nohttp,
		Hexdump:		*hexdump,
		Hexdumppkt:		*hexdumppkt,
		Iface: 			*iface,
		Fname:			*fname,
		Snaplen:		*snaplen,
		Promisc:		*promisc,
		Output: 		*output,
		Decrypt: 		*decrypt,
		SSLKeyLog: 		*sslkeylog,
	}
}


func main() {
	flag.Parse()
	// 设置日志级别
	SetLogLevel()

	var pcapHandle = packet.NewPcapHandler(flag.Args(), SetCommandLine())

	// 选择抓包方式
	pcapHandle.SetPcapMode()
	// BPF 语句设置
	pcapHandle.SetBPF()
	// 设置 解码器
	pcapHandle.SetDecoder()

	streamFactory := packet.NewStreamFactory(pcapHandle)

	streamFactory.Run()
	// streamFactory.Show()
}