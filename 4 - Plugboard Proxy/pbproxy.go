/*
	In this assignment you will develop a "plugboard" proxy for adding an extra
	layer of protection to publicly accessible network services. Your program will
	be written in Go using the Crypto library.

	Consider for example the case of an SSH server with a public IP address. No
	matter how securely the server has been configured and how strong the keys
	used are, it might suffer from a "pre-auth" zero day vulnerability that allows
	remote code execution even before the completion of the authentication
	process. This could allow attackers to compromise the server even without
	providing proper authentication credentials. The Heartbleed OpenSSL bug is an
	example of such a serious vulnerability against SSL/TLS.

	The plugboard proxy you are going to develop, named 'pbproxy', adds an extra
	layer of encryption to connections towards TCP services. Instead of connecting
	directly to the service, clients connect to pbproxy (running on the same
	server), which then relays all traffic to the actual service. Before relaying
	the traffic, pbproxy *always* decrypts it using a static symmetric key. This
	means that if the data of any connection towards the protected server is not
	properly encrypted, then it will turn into garbage before reaching the
	protected service.

	This is a better option than port knocking and similar solutions, as attackers
	who might want to exploit a zero day vulnerability in the protected service
	would first have to know the secret key for having a chance to successfully
	deliver their attack vector to the server. This of course assumes that the
	plugboard proxy does not suffer from any vulnerability itself. Given that its
	task and its code are much simpler compared to an actual service (e.g., an SSH
	server), its code can be audited more easily and it can be more confidently
	exposed as a publicly accessible service. Go is also a memory-safe language
	that does not suffer from memory corruption bugs.

	Clients who want to access the protected server should proxy their traffic
	through a local instance of pbroxy, which will encrypt the traffic using the
	same symmetric key used by the server. In essence, pbproxy can act both as
	a client-side proxy and as server-side reverse proxy, in a way similar to
	netcat.

	Your program should conform to the following specification:

	go run pbproxy.go [-l listenport] -p pwdfile destination port

	  -l  Reverse-proxy mode: listen for inbound connections on <listenport> and
	      relay them to <destination>:<port>

	  -p  Use the ASCII text passphrase contained in <pwdfile>

	* In client mode, pbproxy reads plaintext traffic from stdin and transmits it
	  in encrypted form to <destination>:<port>

	* In reverse-proxy mode, pbproxy should continue listening for incoming
	  connections after a previous session is terminated, and it should be able to
	  handle multiple concurrent connections (all using the same key).

	* Data should be encrypted/decrypted using AES-256 in GCM mode (bi-directional
	  communication). You should derive an appropriate AES key from the supplied
	  passphrase using PBKDF2.

	Going back to the SSH example, let's see how pbproxy can be used to protect an
	SSH server. Assume that we want to protect a publicly accessible sshd running
	on vuln.cs.stonybrook.edu. First, we should configure sshd to listen *only* on
	the localhost interface, making it inaccessible from the public network. Then,
	we fire up a reverse pbproxy instance on the same host listening on port 2222:

	  pbproxy -p mykey -l 2222 localhost 22

	Clients can then connect to the SSH server using the following command:

	  ssh -o "ProxyCommand pbproxy -p mykey vuln.cs.stonybrook.edu 2222" localhost

	This will result in the following data flow:

	ssh <--stdin/stdout--> pbproxy-c <--socket 1--> pbproxy-s <--socket 2--> sshd
	\______________________________/                \___________________________/
	             client                                        server           

	Socket 1 (encrypted): client:randomport <-> server:2222
	Socket 2 (plaintext): localhost:randomport <-> localhost:22
*/

package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"golang.org/x/crypto/pbkdf2"
	"io"
	"hash/fnv"
	"log"
	"net"
	"os"
	"strings"
	"time"
)


type Progress struct {
	bytes uint64
}


func getKey(passphrase string, salt []byte) ([]byte){
	if(len(passphrase) == 0){
		fmt.Println("ERROR: Please enter non-empty passphrase")
		os.Exit(1)
	}
	encryption_key := pbkdf2.Key([]byte(passphrase), salt, 2048, sha256.Size, sha256.New)
	return encryption_key
}


func hash(s string) (string) {
    h := fnv.New32a()
    h.Write([]byte(s))
    return string(h.Sum32())
}

func encryptData(passphrase string, data []byte, salt []byte) ([]byte) {
	if len(passphrase) == 0{
		fmt.Println("ERROR: Please enter non-empty passphrase")
		os.Exit(1)
	}
	encrypt_key := getKey(passphrase, salt)
	cipher_block, err := aes.NewCipher(encrypt_key)
	if err != nil {
		fmt.Println("ERROR:", err)
		os.Exit(1)
	}
	gcm, err := cipher.NewGCM(cipher_block)
	if err != nil {
		fmt.Println("ERROR:", err)
		os.Exit(1)
	}
	size_nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, size_nonce); err != nil {
		fmt.Println("ERROR:", err)
		os.Exit(1)
	}
	return gcm.Seal(size_nonce, size_nonce, data, nil)
}


func decryptData(passphrase string, data []byte, salt []byte) ([]byte) {
	if len(passphrase) == 0{
		fmt.Println("ERROR: PLEASE ENTER NON-EMPTY PASSPHRASE")
		os.Exit(1)
	}
	decrypt_key := getKey(passphrase, salt)
	cipher_block, err := aes.NewCipher(decrypt_key)
	if err != nil {
		fmt.Println("ERROR:", err)
		os.Exit(1)
	}
	gcm, err := cipher.NewGCM(cipher_block)
	if err != nil {
		fmt.Println("ERROR:", err)
		os.Exit(1)
	}
	nonce_len := gcm.NonceSize()
	nonce, cipher_text := data[:nonce_len], data[nonce_len:]
	decrypted, err := gcm.Open(nil, nonce, cipher_text, nil)
	if err != nil {
		fmt.Println("ERROR:", err)
		os.Exit(1)
	}
	return decrypted
}


func clientChannel(conn net.Conn, passphrase string) {
	x := time.Now().Add(time.Minute * time.Duration(5)).Format("1504")
	salt := hash(string(x))
	data := make([]byte, 1000000)
	var w_buffer uint64
	c := make(chan Progress)
	
	sendData := func(reader io.ReadCloser, writer io.WriteCloser) {
		
		defer reader.Close()
		defer writer.Close()

		if reader == conn {
			for {
				read, err := reader.Read(data)
				if err != nil {
					fmt.Println("ERROR: ", err)
					break
				}
				if read != 0 {
					cipher_text := decryptData(passphrase, data[:read], []byte(salt))
					write, err := writer.Write(cipher_text)
					if err != nil {
						fmt.Println("ERROR:", err)
						break
					}
					time.Sleep(time.Millisecond * 120)
					w_buffer += uint64(write)
				}
			}
			c <- Progress{bytes: w_buffer}
		} else {
			for {
				read, err := reader.Read(data)
				if err != nil {
					fmt.Println("ERROR:", err)
					break
				}
				if read != 0 {
					cipher_text := encryptData(passphrase, data[:read], []byte(salt))
					write, err := writer.Write(cipher_text)
					if err != nil {
						fmt.Println("ERROR:", err)
						break
					}
					time.Sleep(time.Millisecond * 120)
					w_buffer += uint64(write)
				}
			}
			c <- Progress{bytes: w_buffer}
		}
	}
	go sendData(conn, os.Stdout)
	go sendData(os.Stdin, conn)
	p := <-c
	p = <-c
	log.Printf("[%s]: Connection terminated, %d bytes sent\n", conn.RemoteAddr(), p.bytes)
}


func serverChannel(conn1 net.Conn, conn2 net.Conn, passphrase string) {
	x := time.Now().Add(time.Minute * time.Duration(5)).Format("1504")
	salt := hash(string(x))
	data := make([]byte, 1000000)
	var w_buffer uint64
	c := make(chan Progress)
	
	sendData := func(reader io.ReadCloser, writer io.WriteCloser) {
		defer reader.Close()
		defer writer.Close()

		if reader == conn1 {
			for {
				read, err := reader.Read(data)
				if err != nil {
					fmt.Println("ERROR:", err)
					break
				}
				if read != 0 {
					cipher_text := decryptData(passphrase, data[:read], []byte(salt))
					write, err := writer.Write(cipher_text)
					if err != nil {
						fmt.Println("ERROR:", err)
						break
					}
					time.Sleep(time.Millisecond * 120)
					w_buffer += uint64(write)
				}
			}
			c <- Progress{bytes: w_buffer}
		} else {
			for {
				read, err := reader.Read(data)
				if err != nil {
					fmt.Println("ERROR:", err)
					break
				}
				if read != 0 {
					cipher_text := encryptData(passphrase, data[:read], []byte(salt))
					write, err := writer.Write(cipher_text)
					if err != nil {
						fmt.Println("ERROR:", err)
						break
					}
					time.Sleep(time.Millisecond * 120)
					w_buffer += uint64(write)
				}
			}
			c <- Progress{bytes: w_buffer}
		}
	}
	go sendData(conn1, conn2)
	go sendData(conn2, conn1)
	p := <-c
	log.Printf("[%s]: Connection terminated, %d bytes received\n", conn1.RemoteAddr(), p.bytes)
	p = <-c
	log.Printf("[%s]: Connection terminated, %d bytes sent\n", conn1.RemoteAddr(), p.bytes)
}


func reverseProxyModeOn(port string, localport string, passphrase string) {
	if(len(port) == 0 || len(localport) == 0 || len(passphrase) == 0){
		fmt.Println("ERROR: Invalid parameters")
		os.Exit(1)
	}
	sconn, err := net.Listen("tcp", ":" + port)
	if err != nil {
		log.Fatalln(err)
		fmt.Println(err)
	}
	fmt.Println("Listening on: 127.0.0.1" + ":" + port)
	for {
		con, err := sconn.Accept()
		if err != nil {
			log.Fatalln(err)
			fmt.Println(err)
		} else {	
		local, err := net.Dial("tcp", "localhost" + ":" + localport)
		if err != nil {
			fmt.Println(err)
		}
		log.Printf("[%s]: Connection established\n", con.RemoteAddr())
		go serverChannel(con, local, passphrase)
		}
	}
}


func clientModeOn(host string, port string, passphrase string) {
	if(len(host) == 0 || len(host) == 0 || len(passphrase) == 0){
		fmt.Println("ERROR: Invalid parameters")
		os.Exit(1)
	}
	conn, err := net.Dial("tcp", host + ":" + port)
	if err != nil {
		log.Fatalln(err)
		fmt.Println(err)
	}
	clientChannel(conn, passphrase)
}


func main() {
	args := os.Args[1:]
	if len(args) < 3{
		fmt.Println("ERROR: PLEASE GIVE PROPER INPUT:")
		fmt.Println("USAGE: go run pbproxy.go [-l lPort] -p pwdfile destination port")
		os.Exit(1)
	}

	dest := ""
	lPort := ""
	passphrase := ""
	
	for i := 0; i < len(args); {
		if args[i] == "-p" {
			passphrase = args[i + 1]
			i = i + 2
		} else if args[i] == "-l" {
			lPort = args[i + 1]
			i = i + 2
		} else {
			if dest == "" {
				dest = args[i]
			} else {
				dest = dest + " " + args[i]
			}
			i += 1
		}
	}

	// storing the content of the file into a string variable
	passphrase = string(passphrase)
	destSplit := strings.Fields(dest)
	destHost := destSplit[0]
	destPort := destSplit[1]
	if lPort != "" {
		// when -l flag is provided, pbproxy need to run as server(reverse proxy)
		reverseProxyModeOn(lPort, destPort, passphrase)
	} else {
		// in case -l is not provided, pbproxy need to run as client(forward proxy)
		clientModeOn(destHost, destPort, passphrase)
	}
}