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

func ip4Checksum(ip4 *layers.IPv4) uint16 {
    sum := 0x4500 + uint32(ip4.Length) + uint32(ip4.Id) + (uint32(ip4.TTL) << 8) + uint32(ip4.Protocol)
    sum += (uint32(ip4.SrcIP[0]) << 8) + uint32(ip4.SrcIP[1])
    sum += (uint32(ip4.SrcIP[2]) << 8) + uint32(ip4.SrcIP[3])
    sum += (uint32(ip4.DstIP[0]) << 8) + uint32(ip4.DstIP[1])
    sum += (uint32(ip4.DstIP[2]) << 8) + uint32(ip4.DstIP[3])
    for sum > 0xFFFF {
        sum = (sum & 0xFFFF) + sum >> 16
    }
    return uint16(-sum-1)
}
func respondToPacket(packetChannel chan *gopacket.Packet, handle *pcap.Handle) {
    var eth layers.Ethernet
    var ip4 layers.IPv4
    var tcp layers.TCP

    curPacket := *<- packetChannel
    decoded := []gopacket.LayerType{}
    parser := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &eth, &ip4, &tcp)
    err := parser.DecodeLayers(curPacket.Data(), &decoded)

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
                    if tcp.DstPort == 80 {
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
        }
        if respEth != nil && respIP4 != nil && respTCP != nil {
            const payloadStr = "HTTP/1.1 404 Not Found\r\n"
            buf := gopacket.NewSerializeBuffer()
            opts := gopacket.SerializeOptions{}
            payload := gopacket.Payload(payloadStr)

            respIP4.Checksum = ip4Checksum(respIP4)
            respTCP.SetNetworkLayerForChecksum(respIP4)
            respTCP.Payload = payload
            respTCP.Checksum, err = respTCP.ComputeChecksum()

            gopacket.SerializeLayers(buf, opts,
                respEth,
                respIP4,
                respTCP,
                payload)
            packetData := buf.Bytes()

            err = handle.WritePacketData(packetData)
            fmt.Printf("Replying to %s::%d\n", ip4.SrcIP.String(), tcp.SrcPort)
            if err != nil {
                fmt.Println(err)
            }
        }
    }
}

func main() {
    var (
        device        string = "eth0"
        snapshot_len  int32  = 1024
        promiscuous   bool   = false
        err           error
        timeout       time.Duration = 30 * time.Second
        handle        *pcap.Handle
        packetSource  chan gopacket.Packet
        lastPacket    gopacket.Packet
        packetChannel chan *gopacket.Packet
    )

    handle, err = pcap.OpenLive(device, snapshot_len, promiscuous, timeout)
    if err != nil { log.Fatal(err) }
    defer handle.Close()

    packetChannel = make(chan *gopacket.Packet)
    packetSource = gopacket.NewPacketSource(handle, handle.LinkType()).Packets()

    for packet := range packetSource {
        if lastPacket == packet {
            continue
        }
        lastPacket = packet
        go respondToPacket(packetChannel, handle)
        packetChannel <- &packet
    }
}
