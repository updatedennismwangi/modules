package net

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"github.com/gorilla/websocket"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	_ "net/http"
	"sync"
	"sync/atomic"
)

type AcceptOptions struct {
	Secure      bool
	Compression bool
	SSLEnabled  bool
}

type SSLConfig struct {
	*AcceptOptions
	Certfile string
	Keyfile  string
	CAfile   string
	Cert     tls.Certificate
}

type PrivateSocket struct {
	Id          int
	Compression bool
	Secure      bool
	SSLEnabled  bool
	Connected   bool
	Type        ServerType
	tcp         *TcpSocket
	ws          *WsSocket
	c           net.Conn
	key         []byte
	block       cipher.Block
	message     *Message
	buffer      *bytes.Buffer
	bufLen      int
	readMux     sync.Mutex
	sendMux     sync.Mutex
	output      chan *bytes.Buffer
	outputClose chan bool
	onMessage   func(netMsg *Message)
	onSend      func(buf *bytes.Buffer)
	onInnerSend func(buf *bytes.Buffer)
	onClose     func()
	OnMessage   func(socket *Socket, netMsg *Message)
	OnError     func(socket *Socket, err Error)
}

type TcpSocket struct {
	*PrivateSocket
	Offset int
}

func NewTcpSocket(options *AcceptOptions, conn net.Conn) *Socket {
	sf := NewSocket(options, conn)
	sf.TcpSocket = &TcpSocket{PrivateSocket: sf.PrivateSocket}
	sf.buffer = bytes.NewBuffer(make([]byte, 4194304))
	sf.Type = TCP
	//if sf.Secure {
	//	sf.onInnerSend = sf.onSecureWsSend
	//	sf.onMessage = sf.onSecureMessage
	//} else {
	//	sf.onMessage = sf.onPlainMessage
	//	sf.onInnerSend = sf.onPlainWsSend
	//}
	return sf
}

type WsSocket struct {
	*PrivateSocket
	WsSock    *websocket.Conn
	WssSecure bool
}

func NewWsSocket(options *AcceptOptions, conn *websocket.Conn) *Socket {
	sf := NewSocket(options, conn.UnderlyingConn())
	sf.WsSocket = &WsSocket{PrivateSocket: sf.PrivateSocket, WsSock: conn}
	sf.buffer = bytes.NewBuffer(make([]byte, 4194304))
	sf.Type = WSS
	if sf.Secure {
		sf.onInnerSend = sf.onSecureWsSend
		sf.onMessage = sf.onSecureMessage
	} else {
		sf.onMessage = sf.onPlainMessage
		sf.onInnerSend = sf.onPlainWsSend
	}
	return sf
}

type Socket struct {
	*PrivateSocket
	*WsSocket
	*TcpSocket
}

func NewSocket(options *AcceptOptions, conn net.Conn) *Socket {
	sf := new(Socket)
	sf.PrivateSocket = &PrivateSocket{c: conn}
	if options != nil {
		sf.Secure = options.Secure
		sf.SSLEnabled = options.SSLEnabled
		sf.Compression = options.Compression
	}
	sf.message = &Message{}
	if sf.Secure {
		sf.key = []byte("ImpassphrasegoodImpassphrasegood")
		sf.block, _ = aes.NewCipher(sf.key)
		sf.onMessage = sf.onSecureMessage
		sf.onInnerSend = sf.onSecureTcpSend
	} else {
		sf.onMessage = sf.onPlainMessage
		sf.onInnerSend = sf.onPlainTcpSend
	}
	sf.output = make(chan *bytes.Buffer, 100)
	sf.outputClose = make(chan bool, 2)
	return sf
}

func (sf *Socket) String() string {
	return fmt.Sprintf("%d | %d | %s | %s", sf.Type, sf.Id, sf.c.RemoteAddr().Network(), sf.c.RemoteAddr().String())
}

func (sf *Socket) onPlainMessage(netMsg *Message) {
	sf.OnMessage(sf, netMsg)
}

func (sf *Socket) onSecureMessage(netMsg *Message) {
	v := hmac.New(sha256.New, sf.key)
	_, _ = v.Write(netMsg.Data.Bytes()[:netMsg.Length-32])
	if bytes.Compare(v.Sum(nil), netMsg.Data.Bytes()[netMsg.Length-32:netMsg.Length]) == 0 {
		ecb := cipher.NewCBCDecrypter(sf.block, netMsg.Data.Bytes()[:aes.BlockSize])
		ecb.CryptBlocks(
			netMsg.Data.Bytes()[aes.BlockSize:netMsg.Length-32],
			netMsg.Data.Bytes()[aes.BlockSize:netMsg.Length-32])
		netMsg.Length = uint64(
			copy(netMsg.Data.Bytes()[:netMsg.Length],
				netMsg.Data.Bytes()[aes.BlockSize:int(netMsg.Length)-(32+int(netMsg.Data.Bytes()[netMsg.Length-33]))]),
		)
		//if sf.onMessage == nil {
		//	fmt.Println("Problem in socket", sf.c.RemoteAddr())
		//	sf.onClose()
		//} else {
		sf.OnMessage(sf, netMsg)
		//}
	} else {
		sf.onClose()
	}
}

func (sf *Socket) onPlainTcpSend(buf *bytes.Buffer) {
	buf.Write(bytes.Repeat([]byte{byte(0)}, HeaderLenPlain))
	copy(buf.Bytes()[HeaderLenPlain:], buf.Bytes()[:buf.Len()-HeaderLenPlain])
	binary.LittleEndian.PutUint64(buf.Bytes()[:8], uint64(buf.Len()-HeaderLenPlain))
	_, writeErr := sf.c.Write(buf.Bytes())
	if writeErr != nil {
		sf.OnError(sf, Error{NetworkErrorWrite, writeErr})
		sf.onClose()
	}
}

func (sf *Socket) onSecureTcpSend(buf *bytes.Buffer) {
	sf.encrypt(buf)
	sf.onPlainTcpSend(buf)
}

func (sf *Socket) encrypt(buf *bytes.Buffer) {
	padding := HeaderLenSecure - (buf.Len() % HeaderLenSecure)
	buf.Write(bytes.Repeat([]byte{byte(padding)}, padding))
	buf.Write(bytes.Repeat([]byte{byte(0)}, HeaderLenSecure))
	copy(buf.Bytes()[HeaderLenSecure:], buf.Bytes()[:buf.Len()-HeaderLenSecure])
	_, _ = rand.Read(buf.Bytes()[:HeaderLenSecure])
	ecb := cipher.NewCBCEncrypter(sf.block, buf.Bytes()[:HeaderLenSecure])
	ecb.CryptBlocks(
		buf.Bytes()[HeaderLenSecure:],
		buf.Bytes()[HeaderLenSecure:])
	v := hmac.New(sha256.New, sf.key)
	_, _ = v.Write(buf.Bytes())
	buf.Write(v.Sum(nil))
}

func (sf *Socket) onPlainWsSend(buf *bytes.Buffer) {
	writeErr := sf.WsSock.WriteMessage(websocket.BinaryMessage, buf.Bytes())
	if writeErr != nil {
		sf.OnError(sf, Error{NetworkErrorWrite, writeErr})
		sf.onClose()
	}
	//var err error
	//ack := ws.NewTextFrame(buf.Bytes())
	//if sf.Secure {
	//	ack.Header.OpCode = ws.OpBinary
	//}
	//if sf.Compression {
	//	ack, err = wsflate.CompressFrame(ack)
	//	if err != nil {
	//		sf.OnError(sf, Error{NetworkWssCompress, err})
	//		sf.onClose()
	//		return
	//	}
	//}
	//if writeErr := ws.WriteFrame(sf.c, ack); writeErr != nil {
	//	sf.OnError(sf, Error{NetworkErrorWrite, writeErr})
	//	sf.onClose()
	//	return
	//}
}

func (sf *Socket) onSecureWsSend(buf *bytes.Buffer) {
	sf.encrypt(buf)
	sf.onPlainWsSend(buf)
}

func (sf *Socket) read() {
	sf.message.Data = bytes.NewBuffer(make([]byte, 4194304))
	go func() {
		switch sf.Type {
		case TCP:
			{
				for {
					_, headerErr := io.ReadFull(sf.c, sf.message.Data.Bytes()[:8])
					if headerErr != nil {
						sf.OnError(sf, Error{NetworkErrorHead, headerErr})
						sf.onClose()
						return
					}
					_ = binary.Read(bytes.NewBuffer(sf.message.Data.Bytes()[:8]),
						binary.LittleEndian, &sf.message.Length)
					if int(sf.message.Length) > sf.message.Data.Len() {
						sf.message.Data.Grow(int(sf.message.Length+8) - sf.message.Data.Len())
					}

					nu, bodyErr := io.ReadFull(sf.c, sf.message.Data.Bytes()[:sf.message.Length])
					if bodyErr != nil {
						sf.OnError(sf, Error{NetworkErrorHead, bodyErr})
						sf.onClose()
						return
					}
					if nu == int(sf.message.Length) {
						sf.onMessage(sf.message)
						sf.message.Length = 0
						sf.bufLen = 0
					} else {
						fmt.Println("I am getting incomplete messages", sf.message.Length, nu, bodyErr)
					}
				}
			}
		case WSS:
			{
				for {
					mt, message, err := sf.WsSock.ReadMessage()
					if err != nil {
						sf.OnError(sf, Error{NetworkErrorHead, err})
						sf.onClose()
						return
					}
					sf.message.Length = uint64(len(message))
					switch mt {
					case websocket.CloseMessage:
						{
							sf.onClose()
							return
						}
					case websocket.TextMessage:
					case websocket.BinaryMessage:
						{
							if sf.message.Data.Cap() < int(sf.message.Length) {
								sf.message.Data.Grow(int(sf.message.Length) - sf.message.Data.Cap())
							}
							sf.message.Data.Reset()
							sf.message.Data.Write(message)
							sf.onMessage(sf.message)
						}
					}
				}
			}
		}
	}()
}

func (sf *Socket) write() {
	go func() {
		for {
			select {
			case buf := <-sf.output:
				{
					sf.onInnerSend(buf)
					continue

				}
			case _ = <-sf.outputClose:
				{
					return
				}
			}
		}
	}()
}

func (sf *Socket) Send(buffer *bytes.Buffer) {
	sf.PrivateSocket.onSend(buffer)
}

type PrivateSocketServer struct {
	G            *GServer
	ServerType   ServerType
	Interface    *Interface
	Config       *SSLConfig
	tcp          *TCPServer
	ws           *WsServer
	listener     net.Listener
	tlsListener  tls.Config
	OnConnect    func(socket *Socket)
	OnDisconnect func(socket *Socket)
	OnMessage    func(socket *Socket, netMsg *Message)
	OnError      func(socket *Socket, err Error)
	Sockets      map[int]*Socket
	SMux         sync.RWMutex
}

func NewPrivateSocketServer(serverType ServerType, netInterface Interface, config *SSLConfig) *PrivateSocketServer {
	sf := new(PrivateSocketServer)
	sf.ServerType = serverType
	sf.Interface = &netInterface
	sf.Sockets = map[int]*Socket{}
	if config == nil {
		sf.Config = &SSLConfig{AcceptOptions: &AcceptOptions{Secure: false}}
	} else {
		sf.Config = config
	}
	return sf
}

func (sf *PrivateSocketServer) Listen() {
	switch sf.ServerType {
	case TCP:
		{
			sf.tcp.tcpListen()
		}
	case WSS:
		{
			sf.ws.wsListen()
		}
	}
}

func (sf *PrivateSocketServer) Exit() {
	if sf.listener != nil {
		_ = sf.listener.Close()
	}
}

type TCPServer struct {
	*PrivateSocketServer
}

func NewTCPServer(server *PrivateSocketServer) *TCPServer {
	sf := new(TCPServer)
	sf.PrivateSocketServer = server
	return sf
}

func (sf *TCPServer) AcceptRawConn(conn net.Conn) *Socket {
	socket := NewTcpSocket(sf.Config.AcceptOptions, conn)
	socket.Id = int(sf.G.connId.Add(1))
	sf.SMux.Lock()
	sf.Sockets[socket.Id] = socket
	sf.SMux.Unlock()
	socket.OnMessage = sf.OnMessage
	socket.OnError = sf.OnError
	socket.onClose = func() {
		_ = socket.c.Close()
		socket.outputClose <- true
		socket.Connected = false
		sf.OnDisconnect(socket)
		sf.SMux.Lock()
		delete(sf.Sockets, socket.Id)
		sf.SMux.Unlock()
	}
	socket.onSend = func(buf *bytes.Buffer) {
		if len(socket.output) > 90 {
			return
		}
		socket.output <- buf
	}
	socket.Connected = true
	sf.OnConnect(socket)
	socket.read()
	socket.write()
	return socket
}

func (sf *TCPServer) tcpListen() {
	var err error
	sf.listener, err = net.Listen(sf.Interface.Network, sf.Interface.Address)
	if err != nil {
		panic(err) // TODO:: PANICS WHEN ERROR LISTEN
		return
	}
	go func() {
		for {
			con, acceptErr := sf.listener.Accept()
			if acceptErr != nil {
				fmt.Println(acceptErr)
				break
			}
			sf.AcceptRawConn(con)
		}
	}()
}

type WsServer struct {
	*PrivateSocketServer
	Upgrader websocket.Upgrader
	//Upgrader  *ws.Upgrader
	//Header    ws.HandshakeHeaderHTTP
	//Extension wsflate.Extension
	RootCAs *x509.CertPool
}

func NewWsServer(server *PrivateSocketServer) *WsServer {
	sf := new(WsServer)
	sf.PrivateSocketServer = server
	//sf.Header = ws.HandshakeHeaderHTTP(http.Header{
	//	"X-TRADER": []string{runtime.Version()},
	//})
	//sf.Extension = wsflate.Extension{
	//	Parameters: wsflate.DefaultParameters,
	//}
	//sf.Upgrader = &ws.Upgrader{
	//	ReadBufferSize:  ws.DefaultClientReadBufferSize,
	//	WriteBufferSize: ws.DefaultServerWriteBufferSize,
	//	Negotiate:       sf.Extension.Negotiate,
	//	Protocol: func(i []byte) bool {
	//		return true
	//	},
	//	OnHost: func(host []byte) error {
	//		return nil
	//		nu := strings.Split(string(host), ":")
	//		for _, n := range server.Config.Cert.Leaf.DNSNames {
	//			if n == nu[0] {
	//				return nil
	//			}
	//		}
	//		return nil
	//		//return ws.RejectConnectionError(
	//		//	ws.RejectionStatus(403),
	//		//	ws.RejectionHeader(ws.HandshakeHeaderString(
	//		//		"X-Want-Host: authority.com\r\n",
	//		//	)),
	//		//)
	//	},
	//	OnHeader: func(key, value []byte) error {
	//		if string(key) != "Cookie" {
	//			return nil
	//		}
	//		ok := httphead.ScanCookie(value, func(key, value []byte) bool {
	//			// Check session here or do some other stuff with cookies.
	//			// Maybe copy some values for future use.
	//			return true
	//		})
	//		if ok {
	//			return nil
	//		}
	//		return ws.RejectConnectionError(
	//			ws.RejectionReason("bad cookie"),
	//			ws.RejectionStatus(400),
	//		)
	//	},
	//	OnBeforeUpgrade: func() (ws.HandshakeHeader, error) {
	//		return sf.Header, nil
	//	},
	//}

	return sf
}

func (sf *WsServer) AcceptConn(conn *websocket.Conn) *Socket {
	//handshake, err := sf.Upgrader.Upgrade(con)
	opts := &AcceptOptions{
		SSLEnabled: sf.Config.SSLEnabled,
	}
	//if err != nil {
	//	log.Printf("upgrade error: %s", err)
	//	return nil
	//}
	//if _, ok := sf.Extension.Accepted(); !ok {
	//	opts.Compression = false
	//} else {
	//	opts.Compression = true
	//}
	//opts.Secure = handshake.Protocol == "secure"
	socket := NewWsSocket(opts, conn)
	socket.Id = int(sf.G.connId.Add(1))
	sf.SMux.Lock()
	sf.Sockets[socket.Id] = socket
	sf.SMux.Unlock()
	socket.OnMessage = sf.OnMessage
	socket.OnError = sf.OnError
	socket.onClose = func() {
		_ = socket.c.Close()
		socket.outputClose <- true
		socket.Connected = false
		sf.OnDisconnect(socket)
		sf.SMux.Lock()
		delete(sf.Sockets, socket.Id)
		sf.SMux.Unlock()
	}
	socket.onSend = func(buf *bytes.Buffer) {
		if len(socket.output) > 90 {
			return
		}
		socket.output <- buf
	}
	socket.Connected = true
	sf.OnConnect(socket)
	socket.read()
	socket.write()
	return socket
}

func (sf *WsServer) wsListen() {
	var err error
	tls.NewListener(sf.listener, nil)
	if sf.Config.SSLEnabled {
		sf.Config.Cert, err = tls.LoadX509KeyPair(sf.Config.Certfile, sf.Config.Keyfile)
		if err != nil {
			fmt.Printf("Error parsing x509 cert : %v", err)
			return
		}
		// Get the SystemCertPool, continue with an empty pool on error
		sf.RootCAs, _ = x509.SystemCertPool()
		if sf.RootCAs == nil {
			sf.RootCAs = x509.NewCertPool()
		}
		// Read in the cert file
		certs, err := ioutil.ReadFile(sf.Config.CAfile)
		if err != nil {
			fmt.Printf("Failed to append %q to RootCAs: %v", sf.Config.CAfile, err)
		}

		// Append our cert to the system pool
		if ok := sf.RootCAs.AppendCertsFromPEM(certs); !ok {
			fmt.Printf("No certs appended, using system certs only")
		}
		sf.Config.Cert.Leaf, _ = x509.ParseCertificate(sf.Config.Cert.Certificate[0])
		sf.listener, err = tls.Listen(sf.Interface.Network, sf.Interface.Address,
			&tls.Config{Certificates: []tls.Certificate{sf.Config.Cert}, RootCAs: sf.RootCAs})

	} else {
		sf.listener, err = net.Listen(sf.Interface.Network, sf.Interface.Address)
	}
	if err != nil {
		panic(err) // TODO:: PANICS WHEN ERROR LISTEN
		return
	}
	sf.Upgrader.EnableCompression = false
	sf.Upgrader.CheckOrigin = func(r *http.Request) bool {
		return true
	}
	go func() {
		err := http.Serve(sf.listener, sf)
		if err != nil {
			fmt.Println(err)
		}
	}()

}

func (sf *WsServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	c, err := sf.Upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("Upgrading error: %#v\n", err)
		c.Close()
		return
	}
	sf.AcceptConn(c)
}

type NetServer struct {
	*PrivateSocketServer
	*TCPServer
	*WsServer
}

type ServerType int

const (
	TCP ServerType = iota
	WSS
)

func NewNetServer(serverType ServerType, netInterface Interface, config *SSLConfig) *NetServer {
	sf := new(NetServer)
	sf.PrivateSocketServer = NewPrivateSocketServer(serverType, netInterface, config)
	switch serverType {
	case TCP:
		{
			sf.TCPServer = NewTCPServer(sf.PrivateSocketServer)
			sf.PrivateSocketServer.tcp = sf.TCPServer
		}
	case WSS:
		{
			sf.WsServer = NewWsServer(sf.PrivateSocketServer)
			sf.PrivateSocketServer.ws = sf.WsServer
		}
	}
	return sf
}

type GServer struct {
	connId    atomic.Int64
	Servers   map[string]*NetServer
	Sockets   map[int64]*Socket
	socketMux sync.RWMutex
	connMux   sync.RWMutex
	serverMux sync.RWMutex
}

func NewGServer() *GServer {
	sf := new(GServer)
	sf.Servers = map[string]*NetServer{}
	sf.Sockets = map[int64]*Socket{}
	return sf
}

func (sf *GServer) AddServer(server *NetServer) {
	sf.socketMux.Lock()
	server.G = sf
	sf.Servers[server.Interface.Address] = server
	sf.socketMux.Unlock()
}

func (sf *GServer) Listen() {
	sf.serverMux.RLock()
	defer sf.serverMux.RUnlock()
	for _, server := range sf.Servers {
		server.Listen()
	}
}

func (sf *GServer) Exit() {
	sf.serverMux.RLock()
	defer sf.serverMux.RUnlock()
	for _, server := range sf.Servers {
		server.Exit()
	}
}
