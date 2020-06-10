package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"strconv"
)

const PORT = 8000
const serverCrt = "/opt/tls/tlsWithPhrase/server.crt"
const serverKey = "/opt/tls/tlsWithPhrase/server.key"
const caCrtPath = "/opt/tls/tlsWithPhrase/ca.crt"

func main() {
	listener := startTcpServer(PORT)
	for {
		clientConn,err := listener.Accept()
		if err!=nil {
			log.Println(err)
			continue
		}
		go handleTCPConn(clientConn)

	}
}
func startTcpServer(port int) net.Listener {
	listener ,err := net.Listen("tcp",":"+strconv.Itoa(port))
	if err!=nil {
		panic(err)
	}
	return listener
}
func handleTCPConn(conn net.Conn){
	buf := make([]byte,1024)
	for {
		n,err := conn.Read(buf)
		if err!=nil {
			log.Println("handleTCPConn : ",err)
			return
		}
		recvSTR := string(buf[:n])
		if  recvSTR=="STARTTLS" {
			TCP_UPGRADE_TLS(conn)
			return
		}

	}
}
func TCP_UPGRADE_TLS(conn net.Conn) {
	fmt.Printf("%p\n",conn)
	fmt.Printf("%+v\n",conn)
	fmt.Println("Start UPGRADE TCP ... ")
	pool := x509.NewCertPool()
	caCrt,err := ioutil.ReadFile(caCrtPath)
	if err!=nil {
		panic(err)
	}
	pool.AppendCertsFromPEM(caCrt)
	keyByte,err := ioutil.ReadFile(serverKey)
	certS,err := ioutil.ReadFile(serverCrt)
	keyBlock,_ := pem.Decode(keyByte)
	keyDER,err := x509.DecryptPEMBlock(keyBlock,[]byte("test"))
	if err!=nil {
		panic(err)
	}
	keyBlock.Bytes=keyDER
	keyBlock.Headers=nil
	keyPem := pem.EncodeToMemory(keyBlock)
	certificate,err := tls.X509KeyPair(certS,keyPem)
	if err!=nil {
		panic(err)
	}
	tlsConfig := &tls.Config{
		Certificates:                []tls.Certificate{certificate},
		ClientAuth:                  tls.RequireAndVerifyClientCert,
		ClientCAs:                   pool,
		ServerName: 				 "rhel",
		InsecureSkipVerify: 		 false,
		MaxVersion: 				 tls.VersionTLS13,
		MinVersion: 				 tls.VersionTLS13,
	}
	var tlsConn *tls.Conn
	tlsConn = tls.Server(conn,tlsConfig)
	err = tlsConn.Handshake()
	if err!=nil {
		panic(err)
	}
	go handleTLSConn(tlsConn)
}
func handleTLSConn(conn net.Conn) {
	buf := make([]byte,1024)
	for {
		n,err := conn.Read(buf)
		if err!=nil {
			log.Println("handleTLSConn : ",err)
			return
		}
		log.Println("handleTLSConn : ",string(buf[:n]))
	}
}
