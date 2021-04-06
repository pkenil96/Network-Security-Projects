package main

import (
    "fmt"
    "time"
    "strconv"
    "os"
    "github.com/google/gopacket"
    "github.com/google/gopacket/pcap"
    "github.com/google/gopacket/layers"
)

var (
	handle       *pcap.Handle
	eth 	     layers.Ethernet
	ip4          layers.IPv4
	ip6          layers.IPv6
	tcp          layers.TCP
	udp          layers.UDP
	dns          layers.DNS
	payload      gopacket.Payload
)

func stringInSlice(a string, list []string) bool {
    for _, b := range list {
        if b == a {
            return true
        }
    }
    return false
}


func detectDnsAttemptOffline(pcapFile string, bpfFilter string){
	if handle, err := pcap.OpenOffline(pcapFile); err != nil{
		panic(err)
	} else {
		handle.SetBPFFilter(bpfFilter)
		query_map := make(map[int]int)
		response_map := make(map[int]int)
		org_ans := make(map[int][]string)
		timestamp_map := make(map[int]time.Time)

		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
  		for packet := range packetSource.Packets() {
    		udpLayer := packet.Layer(layers.LayerTypeUDP)
    		udp, _ := udpLayer.(*layers.UDP)   	

    		dnsLayer := packet.Layer(layers.LayerTypeDNS)
    	if(dnsLayer != nil){
    		dns, _ := dnsLayer.(*layers.DNS)
    		dnsId := int(dns.ID)
    		last_timestamp := timestamp_map[dnsId]
    		timestamp_map[dnsId] = packet.Metadata().Timestamp

    		for _, dnsQuestion := range dns.Questions {
				domain := string(dnsQuestion.Name)	
				_, found_query := query_map[dnsId]
				_, found_response := response_map[dnsId]		
				if(udp.DstPort == 53){
					if found_query {
						query_map[dnsId] += 1
					} else {
						query_map[dnsId] = 1
					}		
				} else if(udp.DstPort != 53) {
					if found_response {
						response_map[dnsId] += 1
					} else {
						response_map[dnsId] = 1
						org_ans[dnsId] = make([]string, 0, 10)
					}
				}
				for _, dnsAnswer := range dns.Answers {
					if dnsAnswer.IP.String() != "<nil>" {
						org_ans[dnsId] = append(org_ans[dnsId], dnsAnswer.IP.String())
					}
				}
				time_diff := last_timestamp.Sub(timestamp_map[dnsId])
				if(response_map[dnsId] > query_map[dnsId] && time_diff < 1 * time.Second && org_ans[dnsId][0] != org_ans[dnsId][1]){
					t := time.Now()
					timestamp := t.Format(time.RFC3339)
					fmt.Println(fmt.Sprintf("%s DNS poisoning attempt", timestamp))
					fmt.Println(fmt.Sprintf("TXID: %s Request %s", []byte(strconv.FormatInt(int64(dnsId), 16)), domain))
					fmt.Println(fmt.Sprintf("ANSWER 1: [%s]", org_ans[dnsId][0]))
					fmt.Println(fmt.Sprintf("ANSWER 2: [%s]", org_ans[dnsId][1]))
					os.Exit(1)
				}
			}
    	}
	}
  	}
}


func detectDnsAttemptOnline(interfaceName string, bpfFilter string){
	devices, err := pcap.FindAllDevs()
	if err != nil {
		fmt.Println(err)
	}

	handle, err = pcap.OpenLive(devices[0].Name, 1024, true, 1 * time.Second)
	if err != nil {
		fmt.Println(err)
	}
	
	query_map := make(map[int]int)
	response_map := make(map[int]int)
	org_ans := make(map[int][]string)
	timestamp_map := make(map[int]time.Time)

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
  	for packet := range packetSource.Packets() {
    	udpLayer := packet.Layer(layers.LayerTypeUDP)
    	udp, _ := udpLayer.(*layers.UDP)   	

    	dnsLayer := packet.Layer(layers.LayerTypeDNS)
    	if(dnsLayer != nil){
    		dns, _ := dnsLayer.(*layers.DNS)
    		dnsId := int(dns.ID)
    		last_timestamp := timestamp_map[dnsId]
    		timestamp_map[dnsId] = packet.Metadata().Timestamp

    		for _, dnsQuestion := range dns.Questions {
				domain := string(dnsQuestion.Name)	
				_, found_query := query_map[dnsId]
				_, found_response := response_map[dnsId]		
				if(udp.DstPort == 53){
					if found_query {
						query_map[dnsId] += 1
					} else {
						query_map[dnsId] = 1
					}		
				} else if(udp.DstPort != 53) {
					if found_response {
						response_map[dnsId] += 1
					} else {
						response_map[dnsId] = 1
						org_ans[dnsId] = make([]string, 0, 10)
					}
				}
				for _, dnsAnswer := range dns.Answers {
					if dnsAnswer.IP.String() != "<nil>" {
						org_ans[dnsId] = append(org_ans[dnsId], dnsAnswer.IP.String())
					}
				}
				time_diff := last_timestamp.Sub(timestamp_map[dnsId])
				if(response_map[dnsId] > query_map[dnsId] && time_diff < 1 * time.Second && org_ans[dnsId][0] != org_ans[dnsId][1]){
					t := time.Now()
					timestamp := t.Format(time.RFC3339)
					fmt.Println(fmt.Sprintf("%s DNS poisoning attempt", timestamp))
					fmt.Println(fmt.Sprintf("TXID: %s Request %s", []byte(strconv.FormatInt(int64(dnsId), 16)), domain))
					fmt.Println(fmt.Sprintf("ANSWER 1: [%s]", org_ans[dnsId][0]))
					fmt.Println(fmt.Sprintf("ANSWER 2: [%s]", org_ans[dnsId][1]))
					os.Exit(1)
				}
			}
    	}
  	}
}


func main() {
	commandLineArgs := os.Args
	bpfFilter := "udp"
	interfaceName := "all"
	pcapFile := ""
	if len(commandLineArgs) < 1 {
			fmt.Println("Usage:\nsudo go run dnsdetect.go [-i interface] [-r pcap] expression")
			fmt.Println("-i flag expects interface name")
			fmt.Println("-r flag expects .pcap file")
		} else {
			mode := "online"
			if(stringInSlice("-i", commandLineArgs)){
				mode = "online"
			} 
			if(stringInSlice("-r", commandLineArgs)){
				mode = "offline"
			}
			for i, _ := range commandLineArgs{
				if(i == 0){
					continue
				}
				if(commandLineArgs[i] == "-r"){
					pcapFile = commandLineArgs[i+1]
				}
				if(commandLineArgs[i] == "-i"){
					interfaceName = commandLineArgs[i+1]
				}
			}
			if(mode == "online"){
				detectDnsAttemptOnline(interfaceName, bpfFilter)
			} 
			if(mode == "offline"){
				detectDnsAttemptOffline(pcapFile, bpfFilter)
			}
		}
}