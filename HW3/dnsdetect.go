package main

import (
    "fmt"
    "time"
    "log"
    "io/ioutil"
    "strings"
    "os"
    //"strconv"
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

	query_map := make(map[int]int)
	response_map := make(map[int]int)

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
						nquery, found_query := query_map[dnsId]
						nresponse, found_response := response_map[dnsId]
						
						if(udp.DstPort == 53){
							if found_query {
								query_map[dnsId] = nquery + 1
							} else {
								query_map[dnsId] = 1
							}
							
						} else if(udp.DstPort != 53) {
							if found_response {
								response_map[dnsId] = nresponse + 1
							} else {
								response_map[dnsId] = 1
							}
						}
						
						fmt.Println(
							fmt.Sprintf("Queries[%d] = %d",
						 		dnsId, query_map[dnsId]))
						fmt.Println(
							fmt.Sprintf("Responses[%d] = %d",
							 	dnsId, response_map[dnsId]))

						if(response_map[dnsId] > query_map[dnsId]){
							fmt.Println("****Attack Detected****")
							fmt.Sprintf("%d responses found against %d queries for the Transaction ID = %d",
								response_map[dnsId], query_map[dnsId], dnsId )
							os.Exit(1)
						}
					}
				}
			}
		}
	}
}

func main() {
		bpfFilter := "udp"
		interfaceName := "any"
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
		captureLiveTraffic(interfaceName, bpfFilter, hostnames, targetips)
}