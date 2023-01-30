package net

import (
	"bytes"
	"fmt"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"testing"
)

func TestGServer(t *testing.T) {
	g := NewGServer()
	tcpServer := NewNetServer(TCP, Interface{Network: "tcp4", Address: "0.0.0.0:9000"},
		&SSLConfig{AcceptOptions: &AcceptOptions{Secure: true}})
	onConnect := func(socket *Socket) {
		fmt.Printf("Connected : %s", socket)
	}
	onDisconnect := func(socket *Socket) {
		fmt.Printf("Disconnected : %s", socket)
	}
	onMessage := func(socket *Socket, netMsg *Message) {
		fmt.Println(netMsg.Length, string(netMsg.Data.Bytes()[:netMsg.Length]))
		socket.Send(bytes.NewBuffer(netMsg.Data.Bytes()[:netMsg.Length]))
	}
	onError := func(socket *Socket, err Error) {
		fmt.Printf("Error : %s %s", socket, err.Error())
	}

	tcpServer.OnConnect = onConnect
	tcpServer.OnDisconnect = onDisconnect
	tcpServer.OnMessage = onMessage
	tcpServer.OnError = onError
	g.AddServer(tcpServer)

	wssServer := NewNetServer(WSS, Interface{Network: "tcp4", Address: "0.0.0.0:9001"},
		&SSLConfig{
			AcceptOptions: &AcceptOptions{
				SSLEnabled:  true,
				Compression: true,
				Secure:      true},
			Certfile: "/home/update/certs/vbettrader.com/vbettrader.com.pem",
			Keyfile:  "/home/update/certs/vbettrader.com/vbettrader.com.private.pem",
		})
	wssServer.OnConnect = onConnect
	wssServer.OnDisconnect = onDisconnect
	wssServer.OnMessage = onMessage
	wssServer.OnError = onError
	g.AddServer(wssServer)
	// finally
	g.Listen()

	wt := sync.WaitGroup{}
	wt.Add(1)
	c := make(chan os.Signal)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-c
		g.Exit()
		wt.Done()
	}()
	wt.Wait()
}
