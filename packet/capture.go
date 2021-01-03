/**
* @Author: kiosk
* @Mail: weijiaxiang007@foxmail.com
* @Date: 2020/12/27
**/
package packet

import (
	"encoding/hex"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/ip4defrag"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/reassembly"
	"log"
	"os"
	"os/signal"
	"sync"
	"time"
	"tls_decript/mytls"
	"tls_decript/utils"
)

/*
 * The assembler context
 */
type Context struct {
	CaptureInfo gopacket.CaptureInfo
}

func (c *Context) GetCaptureInfo() gopacket.CaptureInfo {
	return c.CaptureInfo
}


var Stats struct {
	ipdefrag            int
	missedBytes         int
	pkt                 int
	sz                  int
	totalsz             int
	rejectFsm           int
	rejectOpt           int
	rejectConnFsm       int
	reassembled         int
	outOfOrderBytes     int
	outOfOrderPackets   int
	biggestChunkBytes   int
	biggestChunkPackets int
	overlapBytes        int
	overlapPackets      int
}


type StreamFactory struct {
	TcpStreamFactory 	*TcpStreamFactory
	UdpStreamFactory 	*UdpStreamFactory
	StreamPool 			*reassembly.StreamPool
	Assembler			*reassembly.Assembler
	Packet      		*PcapPacket
	IPv4Fragment 		*ip4defrag.IPv4Defragmenter

	Start           	time.Time
	Count 				int
	Bytes 				int64

	hexdumppkt, nodefrag, checksum		bool
	maxcount 							int
}


func NewStreamFactory(packet *PcapPacket) *StreamFactory {
	TCPStreamFactory := &TcpStreamFactory{
		doHTTP: !packet.CommandLine.Nohttp,
		doDecrypt: packet.CommandLine.Decrypt != 0,
		decryptPort: layers.TCPPort(packet.CommandLine.Decrypt),
	}
	streamPool := reassembly.NewStreamPool(TCPStreamFactory)

	if packet.CommandLine.Decrypt != 0 && packet.CommandLine.SSLKeyLog == "" {
		utils.Logging.Warn().Msg("Decrypt is enabled, but no SSL key log input")
	}

	if packet.CommandLine.SSLKeyLog != ""{
		mytls.SetKeyLogContent(packet.CommandLine.SSLKeyLog)
	}

	return &StreamFactory{
		TcpStreamFactory: TCPStreamFactory,
		StreamPool   : streamPool,
		Assembler 	 : reassembly.NewAssembler(streamPool),
		Packet		 : packet,
		IPv4Fragment : ip4defrag.NewIPv4Defragmenter(),
		Start 		 : time.Now(),
		Count 		 : int(0),
		Bytes   	 : int64(0),

		//
		hexdumppkt   : packet.CommandLine.Hexdumppkt,
		nodefrag     : packet.CommandLine.Nodefrag,
		checksum     : packet.CommandLine.Checksum,
		maxcount 	 : packet.CommandLine.Maxcount,
	}
}

var errorsCntMapMutex sync.Mutex
var errorsCntMap map[string]uint
var errorsCnt uint


func (s *StreamFactory) Run() {
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, os.Interrupt)

	errorsCntMap = make(map[string]uint)

	for packet := range s.Packet.Source.Packets() {
		s.Count++
		utils.Logging.Debug().Int("PACKET", int(s.Count))
		data := packet.Data()
		s.Bytes += int64(len(data))
		if s.hexdumppkt {
			utils.Logging.Debug().Int("Packet content len", len(data)).Str("Packet content", hex.Dump(data))
		}

		// defrag the IPv4 packet if required
		if !s.nodefrag {
			ip4Layer := packet.Layer(layers.LayerTypeIPv4)
			if ip4Layer == nil {
				continue
			}
			ip4 := ip4Layer.(*layers.IPv4)
			l := ip4.Length
			newip4, err := s.IPv4Fragment.DefragIPv4(ip4)
			if err != nil {
				log.Fatalln("Error while de-fragmenting", err)
			} else if newip4 == nil {
				utils.Logging.Debug().Msg("Fragment...")
				continue // packet fragment, we don't have whole packet yet.
			}

			// Length != l 为出错的表象
			if newip4.Length != l {
				Stats.ipdefrag++
				utils.Logging.Debug().Str("Decoding re-assembled packet: ", string(newip4.NextLayerType()))
				pb, ok := packet.(gopacket.PacketBuilder)
				if !ok {
					panic("Not a PacketBuilder")
				}
				nextDecoder := newip4.NextLayerType()
				_ = nextDecoder.Decode(newip4.Payload, pb)
			}
		}

		tcp := packet.Layer(layers.LayerTypeTCP)
		if tcp != nil {
			tcp := tcp.(*layers.TCP)
			if s.checksum {
				err := tcp.SetNetworkLayerForChecksum(packet.NetworkLayer())  // 检验其上层是否为 ip 协议
				if err != nil {
					utils.Logging.Fatal().Err(err).Msg("Failed to set network layer for checksum")
				}
			}
			c := Context{
				CaptureInfo: packet.Metadata().CaptureInfo,
			}
			Stats.totalsz += len(tcp.Payload)
			s.Assembler.AssembleWithContext(packet.NetworkLayer().NetworkFlow(), tcp, &c)
		}

		done := s.maxcount > 0 && s.Count >= s.maxcount

		if done {
			errorsCntMapMutex.Lock()
			errorMapLen := len(errorsCntMap)
			errorsCntMapMutex.Unlock()
			_, _ = fmt.Fprintf(os.Stderr, "Processed %v packets (%v bytes) in %v (errorsCnt: %v, errTypes:%v)\n", s.Count, s.Bytes, time.Since(s.Start), errorsCnt, errorMapLen)
		}

		select {
		case <-signalChan:
			_, _ = fmt.Fprintf(os.Stderr, "\nCaught SIGINT: aborting\n")
			done = true
		default:
			// NOP: continue
		}
		if done {
			break
		}
	}

	closed := s.Assembler.FlushAll()
	utils.Logging.Debug().Int("Final flush: %d closed", closed)

	// s.StreamPool.Dump()

}

func (s *StreamFactory) Show() {
	s.TcpStreamFactory.WaitGoRoutines()
	utils.Logging.Debug().Str("Dump", s.Assembler.Dump())
	if !s.nodefrag {
		fmt.Printf("IPdefrag:\t\t%d\n", Stats.ipdefrag)
	}
	fmt.Printf("TCP stats:\n")
	fmt.Printf(" missed bytes:\t\t%d\n", Stats.missedBytes)
	fmt.Printf(" total packets:\t\t%d\n", Stats.pkt)
	fmt.Printf(" rejected FSM:\t\t%d\n", Stats.rejectFsm)
	fmt.Printf(" rejected Options:\t%d\n", Stats.rejectOpt)
	fmt.Printf(" reassembled bytes:\t%d\n", Stats.sz)
	fmt.Printf(" total TCP bytes:\t%d\n", Stats.totalsz)
	fmt.Printf(" conn rejected FSM:\t%d\n", Stats.rejectConnFsm)
	fmt.Printf(" reassembled chunks:\t%d\n", Stats.reassembled)
	fmt.Printf(" out-of-order packets:\t%d\n", Stats.outOfOrderPackets)
	fmt.Printf(" out-of-order bytes:\t%d\n", Stats.outOfOrderBytes)
	fmt.Printf(" biggest-chunk packets:\t%d\n", Stats.biggestChunkPackets)
	fmt.Printf(" biggest-chunk bytes:\t%d\n", Stats.biggestChunkBytes)
	fmt.Printf(" overlap packets:\t%d\n", Stats.overlapPackets)
	fmt.Printf(" overlap bytes:\t\t%d\n", Stats.overlapBytes)
	fmt.Printf("errorsCnt: %d\n", errorsCnt)

	for e, _ := range errorsCntMap {
		fmt.Printf(" %s:\t\t%d\n", e, errorsCntMap[e])
	}
}