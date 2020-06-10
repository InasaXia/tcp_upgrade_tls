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
	"time"
)

func main() {
	conn,err := net.Dial("tcp","rhel:8000")
	if err!=nil {
		panic(err)
	}
	conn.Write([]byte("STARTTLS"))
	caCrtPath := "/opt/tls/tlsWithPhrase/ca.crt"
	clientCrt := "/opt/tls/tlsWithPhrase/client.crt"
	clientKey := "/opt/tls/tlsWithPhrase/client.key"
	pool := x509.NewCertPool()
	caCrt,err := ioutil.ReadFile(caCrtPath)
	if err!=nil {
		panic(err)
	}
	pool.AppendCertsFromPEM(caCrt)
	//certificate,err := tls.LoadX509KeyPair(clientCrt,clientKey)
	//if err!=nil {
	//	panic(err)
	//}

	keyByte,err := ioutil.ReadFile(clientKey)
	certS,err := ioutil.ReadFile(clientCrt)
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
		RootCAs:                     pool,
		ServerName: 				 "rhel",
		InsecureSkipVerify: 		 false,
		MaxVersion: 				 tls.VersionTLS13,
		MinVersion: 				 tls.VersionTLS13,
	}
	var tlsConn *tls.Conn
	tlsConn = tls.Client(conn,tlsConfig)
	log.Printf("END UPGRADE TLS ...")
	err = tlsConn.Handshake()
	if err!=nil {
		panic(err)
	}
	for i:=0;i<10;i++ {
		tlsConn.Write([]byte(strconv.Itoa(i)))
		fmt.Println("send ...")
		time.Sleep(time.Second)
	}
	log.Printf("%+v\n",tlsConn.ConnectionState())
}
