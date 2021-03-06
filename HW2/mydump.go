/*
In this assignment you will develop a passive network monitoring application
written in Go using the GoPacket library. Your program, called 'mydump', will
capture the traffic from a network interface in promiscuous mode (or read the
packets from a pcap trace file) and print a record for each packet in its
standard output, much like a simplified version of tcpdump. The user should be
able to specify a BPF filter for capturing a subset of the traffic, and/or a
string pattern for capturing only packets with matching payloads.

Your program should conform to the following specification:

go run mydump.go [-i interface] [-r file] [-s string] expression

-i  Live capture from the network device <interface> (e.g., eth0). If not
    specified, mydump should automatically select a default interface to
    listen on (hint 1). Capture should continue indefinitely until the user
    terminates the program.

-r  Read packets from <file> in tcpdump format (hint 2).

-s  Keep only packets that contain <string> in their payload (after any BPF
    filter is applied). You are not required to implement wildcard or regular
    expression matching. A simple string matching operation should suffice.

<expression> is a BPF filter that specifies which packets will be dumped. If
no filter is given, all packets seen on the interface (or contained in the
trace) should be dumped. Otherwise, only packets matching <expression> should
be dumped.

For each packet, mydump prints a record containing the timestamp, source and
destination MAC addresses, EtherType (as a hexadecimal number), packet length,
source and destination IP addresses, protocol type (you need to support only
"TCP", "UDP", "ICMP", and "OTHER"), source and destination ports (for TCP and
UDP packets), the TCP flags in case of TCP packets, and the raw content of the
packet payload (hint 3). You are free, but not required, to enrich the output
with other useful information from the packet headers (e.g., IP/TCP options,
ICMP message types). You do not need to support any link layer protocol other
than Ethernet. Support for IPv6 is also optional.
*/

package main

import (
    "fmt"
    "os"
    "strings"
    "encoding/hex"
    "regexp"
    "github.com/google/gopacket"
    "github.com/google/gopacket/pcap"
    "github.com/google/gopacket/layers"
)


type generelInfo struct{
	packetLength string
	timestamp string
}

type etherInfo struct{
	srcMac string
	dstMac string
	etherType string
}

type ipInfo struct{
	srcIp string
	dstIp string
	protocolType string
}

type tcpInfo struct{
	srcPort string
	dstPort string
	// tcpFlags string
}

type appInfo struct{
	payload string
}

func getAllLayers(packet gopacket.Packet){
	for _, layer := range packet.Layers(){
		fmt.Println("-", layer.LayerType())
	}
}

func getEthernetLayer(packet gopacket.Packet) (string, string, string){
 	ethernetLayer := packet.Layer(layers.LayerTypeEthernet)
	if ethernetLayer != nil{
		ethernetPacket, _ := ethernetLayer.(*layers.Ethernet)
		return ethernetPacket.SrcMAC.String(), ethernetPacket.DstMAC.String(), ethernetPacket.EthernetType.String()
	} 
	return "", "", ""
}

func getIPv4Layer(packet gopacket.Packet) (string, string, string){
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer != nil{
		ip, _ := ipLayer.(*layers.IPv4)
		protocolType := ip.Protocol.String()
		// if(protocolType != "UDP" || protocolType != "TCP" || protocolType != "ICMP"){
		// 	fmt.Println(protocolType)
		//	protocolType = "OTHER"
		//}
		return ip.SrcIP.String(), ip.DstIP.String(), protocolType  
	} 
	return "", "", ""
}

func getTcpLayer(packet gopacket.Packet) (string, string){
	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer != nil{
		tcp, _ := tcpLayer.(*layers.TCP)
		return tcp.SrcPort.String(), tcp.DstPort.String()
	}
	return "", ""
}

func getApplicationLayer(packet gopacket.Packet, stringArg string) (string) {
	applicationLayer := packet.ApplicationLayer()
	if applicationLayer != nil {
		// Search for a string inside the payload
		if (stringArg != "" && strings.Contains(string(applicationLayer.Payload()), stringArg)) {
			return hex.Dump(applicationLayer.Payload())	
		}
		return hex.Dump(applicationLayer.Payload())
	}
	return ""
}

// null value check needs to be done in the print function
func printPcapLogs(generelInfoObj generelInfo, etherInfoObj etherInfo, ipInfoObj ipInfo, tcpInfoObj tcpInfo, appInfoObj appInfo){
	/*
		timestamp src_mac -> dst_mac type ether_type len packet_length
		src_ip:src_port -> dst_ip:dst_port protocol_type
		payload
	*/
	output := fmt.Sprintf("%s %s -> %s type %s len %s\n",
	 	generelInfoObj.timestamp,
	 	etherInfoObj.srcMac, 
	 	etherInfoObj.dstMac,
	 	etherInfoObj.etherType,
	 	generelInfoObj.packetLength)

	if(ipInfoObj.srcIp != "" && ipInfoObj.dstIp != "" && tcpInfoObj.srcPort != "" && tcpInfoObj.dstPort != ""){
		output += fmt.Sprintf("%s:%s -> %s:%s %s\n", ipInfoObj.srcIp, tcpInfoObj.srcPort, ipInfoObj.dstIp, tcpInfoObj.dstPort, ipInfoObj.protocolType)
	} else if(ipInfoObj.srcIp != "" && ipInfoObj.dstIp != ""){
		output += fmt.Sprintf("%s -> %s %s\n", ipInfoObj.srcIp, ipInfoObj.dstIp, ipInfoObj.protocolType)
	}

	if(appInfoObj.payload != ""){
		output += fmt.Sprintf("%s\n", appInfoObj.payload)
	}

	fmt.Println(output)
}

//func handlePackets(packet gopacket.Packet)

func getTimeStamp(packet string) (string){
	re := regexp.MustCompile("\\s@\\s.*?EST")
	match := re.FindStringSubmatch(packet)

	timestamp := strings.ReplaceAll(match[0], "EST", "")
	timestamp = strings.ReplaceAll(timestamp, "@", "")
	timestamp = strings.ReplaceAll(timestamp, "-0500", "")
	timestamp = strings.TrimSpace(timestamp)
	return timestamp
}

func getPacketLength(packet string) (string){
	re := regexp.MustCompile("[0-9]+")
	match := re.FindStringSubmatch(packet)
	return match[0]
}


func handlePacket(packet gopacket.Packet, stringArg string){
	packetLength := getPacketLength(packet.Dump())
  	timestamp := getTimeStamp(packet.String())
  	generelInfoObj := generelInfo{
  		packetLength: packetLength,
  		timestamp: timestamp,
  	}
  			
  	srcMac, dstMac, etherType := getEthernetLayer(packet)
  	etherInfoObj := etherInfo{
  		srcMac: srcMac,
  		dstMac: dstMac,
  		etherType: etherType,
  	}
  			
  	srcIp, dstIp, protocol := getIPv4Layer(packet)
  	ipInfoObj := ipInfo{
  		srcIp: srcIp,
  		dstIp: dstIp,
  		protocolType: protocol,
  	}
  			
  	srcPort, dstPort := getTcpLayer(packet)
  	tcpInfoObj := tcpInfo{
  		srcPort: srcPort,
  		dstPort: dstPort,
  	}

  	payload := getApplicationLayer(packet, stringArg)
  	appInfoObj := appInfo{
  		payload: payload,
  	}

  	printPcapLogs(generelInfoObj, etherInfoObj, ipInfoObj, tcpInfoObj, appInfoObj)
}

func readPcap(pcapFileName string, stringArg string, bpfFilter string){
	if handle, err := pcap.OpenOffline(pcapFileName); err != nil{
		panic(err)
	} else {
		// handle.SetBPFFilter("tcp and port 80")
		handle.SetBPFFilter(bpfFilter)
		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
		for packet := range packetSource.Packets() {
			handlePacket(packet, stringArg)			
  		}
	}
}


func captureLiveTraffic(interfaceName string, stringArg string, bpfFilter string){
	if handle, err := pcap.OpenLive(interfaceName, 1600, true, pcap.BlockForever); err != nil {
  		//panic(err)
  		fmt.Println("Invalid usage")
  		fmt.Println("Usage:\n\n./mydump [-i interface] [-r pcap] [-s string] [arguments]")
		fmt.Println("-r flag expects .pcap file")
		os.Exit(1)
	} else {
		handle.SetBPFFilter(bpfFilter)
  		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
  		for packet := range packetSource.Packets() {
    		handlePacket(packet, stringArg)
  		}
	}
}


func printAllAvailableInterfaces(){
	ifs, err := pcap.FindAllDevs()
	if len(ifs) == 0{
		fmt.Printf("Warning: no devices found : %s\n", err)
	} else {
		for i := 0; i < len(ifs); i++ {
			fmt.Printf("dev %d: %s (%s)\n", i+1, ifs[i].Name, ifs[i].Description)
		}
	}
}

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

func main() {
	commandLineArgs := os.Args
	if len(commandLineArgs) < 2 {
		fmt.Println("Usage:\n./mydump [-i interface] [-r pcap] [-s string] [arguments]")
		fmt.Println("-r flag expects .pcap file")
		fmt.Println("-i flag expects interface name")
		fmt.Println("You can pick any interface from the following:")
		printAllAvailableInterfaces()
	} else {
		filterMode := "default"
		stringArg := ""
		bpfFilter := ""
		pcapFile := ""
		interfaceName := ""
		
		commandLineArgsCopy := commandLineArgs
		removeItemAtIndexI(0, commandLineArgsCopy)
		if(stringInSlice("-i", commandLineArgs)){
			filterMode = "online"
		} 
		if(stringInSlice("-r", commandLineArgs)){
			filterMode = "offline"
		}
		for i, arg := range commandLineArgs{
			if(commandLineArgs[i] == "-r"){
				pcapFile = commandLineArgs[i+1]
				removeItemAtIndexI(i, commandLineArgsCopy)
			}
			if(commandLineArgs[i] == "-i"){
				interfaceName = commandLineArgs[i+1]
				removeItemAtIndexI(i, commandLineArgsCopy)
			}
			if(commandLineArgs[i] == "-s"){
				stringArg = commandLineArgs[i+1]
				removeItemAtIndexI(i, commandLineArgsCopy)
			}
			if(len(commandLineArgsCopy) != 0){
				bpfFilter = commandLineArgsCopy[0]
			}
		}

		if(filterMode == "default"){
			captureLiveTraffic("wlp6s0", stringArg, bpfFilter)
		} else if(filterMode == "offline"){
			readPcap(pcapFile, stringArg, bpfFilter)
		} else if(filterMode == "online"){
			captureLiveTraffic(interfaceName, stringArg, bpfFilter)
		}
}
