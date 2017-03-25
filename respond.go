package main

import (
    "fmt"
    _ "strings"
    "github.com/google/gopacket"
    "github.com/google/gopacket/layers"
    "log"
    "time"
    "github.com/google/gopacket/pcap"
)

const test = false

var testPacketBytes = []byte {
    0x40, 0xc7, 0x29, 0x30, 0xb1, 0x3c, 0xd0, 0x50, 0x99, 0x73, 0xd1, 0x19, 0x08, 0x00, 0x45, 0x00,
    0x00, 0x73, 0x8d, 0xb1, 0x40, 0x00, 0x40, 0x06, 0xb7, 0xa8, 0xc0, 0xa8, 0x01, 0x0b, 0x68, 0x1b,
    0xcb, 0x5c, 0xb4, 0x42, 0x00, 0x50, 0x80, 0x20, 0x5a, 0x2d, 0xf2, 0xf6, 0x3b, 0xe2, 0x50, 0x18,
    0x00, 0xe5, 0xf5, 0x90, 0x00, 0x00, 0x47, 0x45, 0x54, 0x20, 0x2f, 0x20, 0x48, 0x54, 0x54, 0x50,
    0x2f, 0x31, 0x2e, 0x31, 0x0d, 0x0a, 0x48, 0x6f, 0x73, 0x74, 0x3a, 0x20, 0x77, 0x77, 0x77, 0x2e,
    0x6c, 0x6f, 0x6c, 0x2e, 0x63, 0x6f, 0x6d, 0x0d, 0x0a, 0x55, 0x73, 0x65, 0x72, 0x2d, 0x41, 0x67,
    0x65, 0x6e, 0x74, 0x3a, 0x20, 0x63, 0x75, 0x72, 0x6c, 0x2f, 0x37, 0x2e, 0x34, 0x37, 0x2e, 0x30,
    0x0d, 0x0a, 0x41, 0x63, 0x63, 0x65, 0x70, 0x74, 0x3a, 0x20, 0x2a, 0x2f, 0x2a, 0x0d, 0x0a, 0x0d,
    0x0a,
}

func main() {
    var (
        device       string = "eth0"
        snapshot_len int32  = 1024
        promiscuous  bool   = false
        err          error
        timeout      time.Duration = 30 * time.Second
        handle       *pcap.Handle
        packetSource chan gopacket.Packet
    )

    handle, err = pcap.OpenLive(device, snapshot_len, promiscuous, timeout)
    if err != nil { log.Fatal(err) }
    defer handle.Close()

    if test {
        packetSource = make(chan gopacket.Packet, 1)
        packetSource <- gopacket.NewPacket(testPacketBytes, layers.LayerTypeEthernet, gopacket.Default)
    } else {
        packetSource = gopacket.NewPacketSource(handle, handle.LinkType()).Packets()
    }
    var eth layers.Ethernet
    var ip4 layers.IPv4
    var tcp layers.TCP
    decoded := []gopacket.LayerType{}
    parser := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &eth, &ip4, &tcp)

    for packet := range packetSource {
        go func() {
            err := parser.DecodeLayers(packet.Data(), &decoded)
            if err == nil {
                var respEth *layers.Ethernet
                var respIP4 *layers.IPv4
                var respTCP *layers.TCP

                for _, layerType := range decoded {
                    switch layerType {
                    case layers.LayerTypeEthernet:
                        respEth = &layers.Ethernet{
                            DstMAC: eth.SrcMAC,
                            SrcMAC: eth.DstMAC,
                            EthernetType: layers.EthernetTypeIPv4,
                        }
                    case layers.LayerTypeIPv4:
                        respIP4 = &layers.IPv4{
                            DstIP: ip4.SrcIP,
                            SrcIP: ip4.DstIP,
                            Protocol: layers.IPProtocolTCP,
                            Version: 4,
                            IHL: 5,
                            TTL: 100,
                        }
                    case layers.LayerTypeTCP:
                        respTCP = &layers.TCP{
                            DstPort: tcp.SrcPort,
                            SrcPort: tcp.DstPort,
                            Seq: tcp.Ack,
                            Ack: tcp.Seq + uint32(len(tcp.Payload)),
                            ACK: true,
                            Window: 29,
                            DataOffset: 21,
                        }
                    }
                }
                if respEth != nil && respIP4 != nil && respTCP != nil {
                    const payloadStr = "HTTP/1.1 404 Not Found\r\n"
                    buf := gopacket.NewSerializeBuffer()
                    opts := gopacket.SerializeOptions{}
                    gopacket.SerializeLayers(buf, opts,
                        respEth,
                        respIP4,
                        respTCP,
                        gopacket.Payload(payloadStr))
                    packetData := buf.Bytes()
                    fmt.Printf("Replying to %s::%s\n", ip4.SrcIP.String(), tcp.SrcPort.String())
                    err = handle.WritePacketData(packetData)
                    if err != nil {
                        fmt.Println(err)
                    }
                }
            } else {
                fmt.Println(err)
            }
        }()
    }
}

