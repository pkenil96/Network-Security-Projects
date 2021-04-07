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
	err          error
	payload      gopacket.Payload
)

func removeItemAtIndexI(index int, array [] string){
	array[index] = array[len(array)-1] // Copy last element to index i.
	array[len(array)-1] = ""   // Erase last element (write zero value).
	array = array[:len(array)-1]  
}

func stringInSlice(a string, list []string) bool {
    for _, b := range list {
        if b == a {
            return true
        }
    }
    return false
}

func detectDnsAttackAttempt(source string, expression string, mode string){
	if(mode == "online"){
		handle, err = pcap.OpenLive(source, 1024, true, 1 * time.Second)
		expression = "udp"
		err = handle.SetBPFFilter(expression)
		if err != nil {
			fmt.Printf("ERROR: INVALID BPF FILTER")
		}
	} else {
		handle, err = pcap.OpenOffline(source)
	}

	if err != nil {
		fmt.Println(err)
		os.Exit(1)
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
				if(response_map[dnsId] > query_map[dnsId] && time_diff < 2 * time.Second && len(org_ans) > 1 && org_ans[dnsId][0] != org_ans[dnsId][1]){
					t := time.Now()
					timestamp := t.Format(time.RFC3339)
					fmt.Println(fmt.Sprintf("%s DNS POISONING ATTEMPT", timestamp))
					fmt.Println(fmt.Sprintf("TXID: %s Request %s", []byte(strconv.FormatInt(int64(dnsId), 16)), domain))
					fmt.Println(fmt.Sprintf("ANSWER 1: [%s]", org_ans[dnsId][0]))
					fmt.Println(fmt.Sprintf("ANSWER 2: [%s]", org_ans[dnsId][1]))
					os.Exit(1)
				}
			}
    	}
  	}
  	if(mode == "offline"){
		fmt.Println("NO ATTACK DETECTED IN GIVEN PCAP")
	}
}


func main() {
	commandLineArgs := os.Args
	expression := "udp"
	source := "any"
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

			var indices []int
			for i, _ := range commandLineArgs{
				if(i == 0){
					continue
				}
				if(commandLineArgs[i] == "-r"){
					source = commandLineArgs[i+1]
					indices = append(indices, i)
					indices = append(indices, i + 1)
				}
				if(commandLineArgs[i] == "-i"){
					source = commandLineArgs[i+1]
					indices = append(indices, i)
					indices = append(indices, i + 1)
				}
			}

			for _, val := range indices {
				removeItemAtIndexI(val, commandLineArgs)
			}

			if(len(commandLineArgs) > 1){
				expression = commandLineArgs[1]
			}

			detectDnsAttackAttempt(source, expression, mode)
		}
}