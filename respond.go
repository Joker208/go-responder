package main

import (
    "fmt"
    _ "strings"
    "github.com/google/gopacket"
    _ "github.com/google/gopacket/layers"
    "log"
    "time"
    "github.com/google/gopacket/pcap"
    "github.com/google/gopacket/layers"
)

var (
    device       string = "eth0"
    snapshot_len int32  = 1024
    promiscuous  bool   = false
    err          error
    timeout      time.Duration = 30 * time.Second
    handle       *pcap.Handle
)

func main() {
    // Open device
    handle, err = pcap.OpenLive(device, snapshot_len, promiscuous, timeout)
    if err != nil { log.Fatal(err) }
    defer handle.Close()

    // Use the handle as a packet source to process all packets
    packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
    var eth layers.Ethernet
    var ip4 layers.IPv4
    var tcp layers.TCP
    decoded := []gopacket.LayerType{}
    parser := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &eth, &ip4, &tcp)

    for packet := range packetSource.Packets() {
        err := parser.DecodeLayers(packet.Data(), &decoded)
        if err == nil {
            var respEth *layers.Ethernet
            var respIP4 *layers.IPv4
            var respTCP *layers.TCP

            for _, layerType := range decoded {
                switch layerType {
                    case layers.LayerTypeEthernet:
                        respEth = &layers.Ethernet{
                            DstMAC: eth.SrcMAC, SrcMAC: eth.DstMAC,
                        }
                    case layers.LayerTypeIPv4:
                        respIP4 = &layers.IPv4{
                            DstIP: ip4.SrcIP, SrcIP: ip4.DstIP,
                        }
                    case layers.LayerTypeTCP:
                        respTCP = &layers.TCP{
                            DstPort: tcp.SrcPort, SrcPort: tcp.DstPort,
                        }
                    }
            }

            if respEth != nil && respIP4 != nil && respTCP != nil {
                buf := gopacket.NewSerializeBuffer()
                opts := gopacket.SerializeOptions{}
                gopacket.SerializeLayers(buf, opts,
                    respEth,
                    respIP4,
                    respTCP,
                    gopacket.Payload([]byte{1, 2, 3, 4}))
                packetData := buf.Bytes()
                fmt.Println(packetData)
            }
        }
    }
}

