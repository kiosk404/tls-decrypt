/**
* @Author: kiosk
* @Mail: weijiaxiang007@foxmail.com
* @Date: 2020/12/27
**/
package packet

import (
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/reassembly"
	"sync"
	"github.com/kiosk404/tls-decrypt/tls"
	"github.com/kiosk404/tls-decrypt/tls/tlsx"
	"github.com/kiosk404/tls-decrypt/utils"
)

/*
*
* TCP stream
 */

/* It's a connection (bidirectional) */
type TcpStream struct {
	tcpstate       		*reassembly.TCPSimpleFSM
	optchecker     		reassembly.TCPOptionCheck
	net, transport 		gopacket.Flow
	urls           		[]string
	ident          		string
	fsmerr         		bool
	sync.Mutex

	isHTTP         		bool
	httpReversed   		bool
	isHTTPS				bool
	httpsReversed		bool
	httpClient         	HttpReader
	httpServer         	HttpReader

	isDecrypt			bool
	decryptReversed 	bool
	decryptPort 		int
	tlsClient 			TLSReader
	tlsServer 			TLSReader

	tlsStream 			*tls.TLSStream   // tmp


	clientWindowScale    	int // 次数统计
	serverWindowScale 		int
	clientRetransmission    int
	serverRetransmission 	int
	clientZeroWindow     	int
	serverFullWindow     	int
	clientKeepAlive      	int
	serverKeepAlive 		int
	clientReset				int
	serverReset				int
}


/*
 * The TCP factory: returns a new Stream
 */
type TcpStreamFactory struct {
	WG     		sync.WaitGroup
	doHTTP, doDecrypt, hexdump 	bool
	decryptPort layers.TCPPort
	output 		string
}

func (factory *TcpStreamFactory) WaitGoRoutines() {
	factory.WG.Wait()
}

func (factory TcpStreamFactory) New(netFlow, transport gopacket.Flow, tcp *layers.TCP, ac reassembly.AssemblerContext) reassembly.Stream {

	utils.Logging.Debug().Msgf("* NEW: %s %s\n", netFlow, transport)
	fsmOptions := reassembly.TCPSimpleFSMOptions{
		SupportMissingEstablishment: true,
	}

	stream := &TcpStream{
		net:        	netFlow,
		transport:  	transport,
		isHTTP:     	(tcp.SrcPort == 80 || tcp.DstPort == 80) && factory.doHTTP,
		httpReversed: 	tcp.SrcPort == 80,
		isHTTPS: 		(tcp.SrcPort == 443 || tcp.DstPort == 443) && factory.doHTTP,
		httpsReversed: 	tcp.SrcPort == 443,
		isDecrypt : 	(tcp.SrcPort == factory.decryptPort || tcp.DstPort == factory.decryptPort) && factory.doDecrypt,
		decryptReversed: tcp.SrcPort == factory.decryptPort,
		tlsStream:      tls.NewTLSStream(),

		tcpstate:   	reassembly.NewTCPSimpleFSM(fsmOptions),   	// 不记录缺少 SYN 的流
		ident:      	fmt.Sprintf("%s:%s", netFlow, transport), 	// 例如 10.2.203.95->122.14.230.144:54367->2018
		optchecker: 	reassembly.NewTCPOptionCheck(),   			// 创建一个默认的 Option ,内容有 mss ,scale, receiveWindow
		clientRetransmission:	0,
		serverRetransmission:   0,
		clientReset: 0,
		serverReset: 0,
	}

	factoryWG := 0
	if stream.isHTTP || stream.isHTTPS{
		factoryWG ++
		stream.httpClient = NewHTTPReader(stream,netFlow, transport,true,factory.hexdump)
		stream.httpServer = NewHTTPReader(stream,netFlow.Reverse(),transport.Reverse(),false,factory.hexdump)
	}
	if stream.isDecrypt {
		factoryWG ++
		stream.tlsClient = NewTLSReader(stream, netFlow, transport, true, factory.hexdump, stream.tlsStream)
		stream.tlsServer = NewTLSReader(stream, netFlow.Reverse(), transport.Reverse(), false, factory.hexdump, stream.tlsStream)
	}
	factory.WG.Add(factoryWG)
	if stream.isHTTP || stream.isHTTPS {
		go stream.httpClient.run(&factory.WG)
		go stream.httpServer.run(&factory.WG)
	}
	if stream.isDecrypt {
		go stream.tlsClient.run(&factory.WG)
		go stream.tlsServer.run(&factory.WG)
	}

	return stream
}


func (t *TcpStream) Accept(tcp *layers.TCP, ci gopacket.CaptureInfo, dir reassembly.TCPFlowDirection, nextSeq reassembly.Sequence, start *bool, ac reassembly.AssemblerContext) bool {
	length := len(tcp.Payload)
	if nextSeq != -1 {
		diff := nextSeq.Difference(reassembly.Sequence(tcp.Seq))
		if reassembly.TCPDirClientToServer == dir {
			if diff == -1 && (length == 1 || length == 0) {
				// This is probably a Keep-alive
				// TODO: check byte is ok
			} else if diff < 0 {
				t.clientRetransmission ++
			}
		}else {
			if diff == -1 && (length == 1 || length == 0) {
				// This is probably a Keep-alive
				// TODO: check byte is ok
			} else if diff < 0 {
				t.serverRetransmission ++
			}
		}
	}

	// FSM
	if !t.tcpstate.CheckState(tcp, dir) {
		utils.Logging.Error().Msgf("FSM", "%s: Packet rejected by FSM (state:%s)\n", t.ident, t.tcpstate.String())

		Stats.rejectFsm++
		if !t.fsmerr {
			t.fsmerr = true
			Stats.rejectConnFsm++
		}
	}

	// Options
	err := t.optchecker.Accept(tcp, ci, dir, nextSeq, start)
	if err != nil {
		utils.Logging.Error().Msgf("OptionChecker", "%s: Packet rejected by OptionChecker: %s\n", t.ident, err)

		Stats.rejectOpt++
	}

	return true
}

func (t *TcpStream) ReassembledSG(sg reassembly.ScatterGather, ac reassembly.AssemblerContext) {
	dir, start, end, skip := sg.Info() // client->server, false, false, 0
	length, saved := sg.Lengths()
	// update stats
	sgStats := sg.Stats()

	if skip > 0 {
		Stats.missedBytes += skip  // 没有捕捉到的字节数
	}
	Stats.sz += length - saved
	Stats.pkt += sgStats.Packets  // 数据包的个数
	if sgStats.Chunks > 1 {       // 只要是有负载的数据包，非纯ACK的包都有 sgStats 属性 （三次握手和四次挥手除外）
		Stats.reassembled++
	}
	Stats.outOfOrderPackets += sgStats.QueuedPackets  // 乱序包数
	Stats.outOfOrderBytes += sgStats.QueuedBytes      // 乱序字节
	if length > Stats.biggestChunkBytes {
		Stats.biggestChunkBytes = length              // 所传的最大一个包的所带的字节数
	}
	if sgStats.Packets > Stats.biggestChunkPackets {  // 数据包个数
		Stats.biggestChunkPackets = sgStats.Packets
	}
	if sgStats.OverlapBytes != 0 && sgStats.OverlapPackets == 0 {
		fmt.Printf("bytes:%d, pkts:%d\n", sgStats.OverlapBytes, sgStats.OverlapPackets)
		panic("Invalid overlap")
	}

	Stats.overlapBytes += sgStats.OverlapBytes
	Stats.overlapPackets += sgStats.OverlapPackets

	var ident string
	if dir == reassembly.TCPDirClientToServer {
		ident = fmt.Sprintf("%v %v(%s): ", t.net, t.transport, dir)
	} else {
		ident = fmt.Sprintf("%v %v(%s): ", t.net.Reverse(), t.transport.Reverse(), dir)
	}
	utils.Logging.Debug().Msgf("%s: SG reassembled packet with %d bytes (start:%v,end:%v,skip:%d,saved:%d,nb:%d,%d,overlap:%d,%d)\n", ident, length, start, end, skip, saved, sgStats.Packets, sgStats.Chunks, sgStats.OverlapBytes, sgStats.OverlapPackets)

	data := sg.Fetch(length)
	//
	if t.isHTTP {
		if length > 0 {
			if dir == reassembly.TCPDirClientToServer && !t.httpReversed {
				t.httpClient.bytes <- data
			} else {
				t.httpServer.bytes <- data
			}
		}
	}


	if t.isDecrypt {
		if length > 0 {
			var got layers.TLS
			err := got.DecodeFromBytes(data, gopacket.NilDecodeFeedback)

			if dir == reassembly.TCPDirClientToServer && !t.decryptReversed {
				TLSType := uint8(data[0])
				utils.Logging.Info().Uint8("TLS TYPE",TLSType)
				switch TLSType {
				case tlsx.TLSHandShake:
					err = t.tlsStream.UnmarshalHandshake(data, tls.ClientHello)
					if err != nil {
						utils.Logging.Error().Err(err).Msg("client handshake unmarshal fail")
					}
				case tlsx.TLSApplication:
					t.tlsClient.bytes <- data
				default:
					fmt.Println("Unknown TLS type ", TLSType)
				}

			} else {
				TLSType := uint8(data[0])
				switch TLSType {
				case tlsx.TLSHandShake:
					err = t.tlsStream.UnmarshalHandshake(data, tls.ServerHello)
					if err != nil {
						utils.Logging.Error().Err(err).Msg("server handshake unmarshal fail")
					}
					_ = t.tlsStream.EstablishConn()

				case tlsx.TLSApplication:
					t.tlsServer.bytes <- data
				default:
					fmt.Println("Unknown TLS type ", TLSType)
				}
			}
		}
	}

}

func (t *TcpStream) ReassemblyComplete(ac reassembly.AssemblerContext) bool {
	utils.Logging.Debug().Msgf("%s: Connection closed\n", t.ident)
	if t.isHTTP || t.isHTTPS {
		close(t.httpClient.bytes)
		close(t.httpServer.bytes)
	}
	if t.isDecrypt {
		close(t.tlsClient.bytes)
		close(t.tlsServer.bytes)
	}
	// do not remove the connection to allow last ACK
	return false
}

