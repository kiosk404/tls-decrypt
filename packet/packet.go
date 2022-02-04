/**
* @Author: kiosk
* @Mail: weijiaxiang007@foxmail.com
* @Date: 2020/12/27
**/
package packet

import (
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"strings"
	"time"
	"github.com/kiosk404/tls-decript/utils"
)


type PcapPacket struct {
	Handle 			*pcap.Handle
	Arg    			[]string
	CommandLine 	utils.Command
	Decoder 		gopacket.Decoder
	Source  		*gopacket.PacketSource
}


func NewPcapHandler(Arg []string, CommandLine utils.Command) *PcapPacket {
	return &PcapPacket{
		Arg: Arg,
		CommandLine: CommandLine,
	}
}

func (p *PcapPacket) SetPcapMode() {
	var err error
	// Offline Mode 离线模式
	if p.CommandLine.Fname != "" {
		if p.Handle, err = pcap.OpenOffline(p.CommandLine.Fname); err != nil {
			utils.Logging.Fatal().Err(err).Msg("PCAP OpenOffline error")
		}
	} else {
		// Live Mode 抓包模式
		inactive, err := pcap.NewInactiveHandle(p.CommandLine.Iface)
		if err != nil {
			utils.Logging.Fatal().Err(err).Msg("could not create")
		}
		defer inactive.CleanUp()
		if err = inactive.SetSnapLen(p.CommandLine.Snaplen); err != nil {
			utils.Logging.Fatal().Err(err).Msg("could not set snap length")
		} else if err = inactive.SetPromisc(p.CommandLine.Promisc); err != nil {
			utils.Logging.Fatal().Err(err).Msg("could not set promisc mode")
		} else if err = inactive.SetTimeout(time.Second); err != nil {
			utils.Logging.Fatal().Err(err).Msg("could not set timeout")
		}

		if p.Handle, err = inactive.Activate(); err != nil {
			utils.Logging.Fatal().Err(err).Msg("PCAP Activate error")
		}
		defer p.Handle.Close()
	}
}

func (p *PcapPacket) SetBPF() {
	if len(p.Arg) > 0 {
		bpffilter := strings.Join(p.Arg, " ")
		utils.Logging.Info().Str("bpffilter", bpffilter).Msg("Using BPF filter")
		if err := p.Handle.SetBPFFilter(bpffilter); err != nil {
			utils.Logging.Fatal().Err(err).Msg("BPF filter error:")
		}
	}
}


func (p *PcapPacket) SetDecoder() {
	var ok bool
	decoderName := p.CommandLine.Decoder // 默认为 Ethernet 为第一层的解码器
	if decoderName == "" {
		decoderName = fmt.Sprintf("%s", p.Handle.LinkType())
	}
	if p.Decoder, ok = gopacket.DecodersByLayerName[decoderName]; !ok {
		utils.Logging.Fatal().Msg("No decoder named: " + decoderName)
	}

	source := gopacket.NewPacketSource(p.Handle, p.Decoder)
	source.Lazy = p.CommandLine.Lazy
	source.NoCopy = true
	source.DecodeStreamsAsDatagrams = true
	p.Source = source

	utils.Logging.Info().Msg("Starting to read packets")
}