package net

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"github.com/mailru/easygo/netpoll"
	"io"
	"net"
	"os"
	"os/signal"
	"sync"
	"sync/atomic"
	"syscall"
)

// ConnWorker represents the worker that executes the job
type ConnWorker struct {
	WorkerId   int
	Mode       int
	WorkerPool chan chan *Conn
	JobChannel chan *Conn
	quit       chan bool
}

func NewConnWorker(workerPool chan chan *Conn, workerId int) ConnWorker {
	return ConnWorker{
		WorkerId:   workerId,
		WorkerPool: workerPool,
		JobChannel: make(chan *Conn),
		quit:       make(chan bool)}
}

// Start method starts the run loop for the worker, listening for a quit channel in
// case we need to stop it
func (w ConnWorker) Start(name string) {
	// Log(INFO,"ConnWorker task :: %d", w.WorkerId)
	go func() {
		buffer := bytes.NewBuffer(make([]byte, 4194304))
		var g func(job *Conn)
		if name == "read" {
			g = func(job *Conn) {
				job.read(buffer)
			}
		} else {
			g = func(job *Conn) {
				job.onSend(<-job.output)
				job.sendMux.Unlock()
			}
		}
		for {
			// register the current worker into the worker queue.
			w.WorkerPool <- w.JobChannel
			select {
			case job := <-w.JobChannel:
				// Log(INFO,"ConnWorker task %d Processing Channel task %v", w.WorkerId, job)
				g(job)
			case <-w.quit:
				// we have received a signal to stop
				// Log(INFO,"ConnWorker task killed %d", w.WorkerId)
				return
			}
		}
	}()
}

// Stop signals the worker to stop listening for work requests.
func (w ConnWorker) Stop() {
	go func() {
		w.quit <- true
	}()
}

type ConnPool struct {
	// A pool of workers channels that are registered with the dispatcher
	Name       string
	WorkerPool chan chan *Conn
	MaxWorkers int
	MaxQueue   int
	JobQueue   chan *Conn
	Workers    []ConnWorker
	Wt         *sync.WaitGroup
}

func NewConnPool(name string, maxWorkers int, maxQueue int) *ConnPool {
	d := &ConnPool{Name: name, MaxWorkers: maxWorkers, MaxQueue: maxQueue}
	d.WorkerPool = make(chan chan *Conn, d.MaxWorkers)
	d.JobQueue = make(chan *Conn, maxQueue)
	d.Workers = []ConnWorker{}
	return d
}

func (d *ConnPool) Run() {
	// starting n number of workers
	for i := 0; i < d.MaxWorkers; i++ {
		worker := NewConnWorker(d.WorkerPool, i)
		d.Workers = append(d.Workers, worker)
		worker.Start(d.Name)
	}
	go d.dispatch()
}

func (d *ConnPool) Stop() {
	for _, worker := range d.Workers {
		worker.Stop()
	}
}

func (d *ConnPool) dispatch() {
	for {
		select {
		case job := <-d.JobQueue:
			// a job request has been received
			go func(job *Conn) {
				if d.Name == "write" {
					job.sendMux.Lock()
				}
				// try to obtain a worker job channel that is available.
				// this will block until a worker is idle
				jobChannel := <-d.WorkerPool
				// dispatch the job to the worker job channel
				jobChannel <- job
			}(job)
		}
	}
}

type JsonPayload struct {
	Cmd  string          `json:"cmd"`
	Body json.RawMessage `json:"body"`
}

type BinaryPayload struct {
	Cmd  string          `json:"cmd"`
	Body json.RawMessage `json:"body"`
}

type Message struct {
	Length uint64
	Data   *bytes.Buffer
}

type ErrorType int

const (
	NetworkErrorOpen ErrorType = iota
	NetworkErrorBody
	NetworkErrorHead
	NetworkErrorWrite
	NetworkWssCompress
)

const (
	HeaderLenPlain  = 8
	HeaderLenSecure = 16
)

type Interface struct {
	Network string
	Address string
}

type Error struct {
	Type ErrorType
	err  error
}

func (sf Error) Error() string {
	return fmt.Sprintf("%v", sf.err)
}

type Conn struct {
	Id           int
	c            net.Conn
	secure       bool
	key          []byte
	message      *Message
	onMessage    func(netMsg *Message)
	onSend       func(buf *bytes.Buffer)
	onClose      func()
	OnMessage    func(netMsg *Message)
	OnError      func(err Error)
	OnConnect    func()
	OnDisconnect func()
	Send         func(buf *bytes.Buffer)
	block        cipher.Block
	mux          sync.Mutex
	sendMux      sync.Mutex
	output       chan *bytes.Buffer
}

func NewConn(conn net.Conn, secure bool) *Conn {
	sf := new(Conn)
	sf.c = conn
	sf.secure = secure
	sf.message = &Message{}
	if secure {
		sf.key = []byte("ImpassphrasegoodImpassphrasegood")
		sf.block, _ = aes.NewCipher(sf.key)
		sf.onMessage = sf.onSecureMessage
		sf.onSend = sf.onSecureSend
	} else {
		sf.onMessage = sf.onPlainMessage
		sf.onSend = sf.onPlainSend
	}
	sf.output = make(chan *bytes.Buffer, 10)
	return sf
}

func (sf *Conn) String() string {
	return fmt.Sprintf("%d | %s | %s", sf.Id, sf.c.RemoteAddr().Network(), sf.c.RemoteAddr().String())
}

func (sf *Conn) IsSecure() bool {
	return sf.secure
}

func (sf *Conn) Close() {
	sf.onClose()
}

func (sf *Conn) onPlainMessage(netMsg *Message) {
	sf.OnMessage(netMsg)
}

func (sf *Conn) onSecureMessage(netMsg *Message) {
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
		sf.OnMessage(netMsg)
	} else {
		sf.onClose()
	}
}

func (sf *Conn) onPlainSend(buf *bytes.Buffer) {
	buf.Write(bytes.Repeat([]byte{byte(0)}, HeaderLenPlain))
	copy(buf.Bytes()[HeaderLenPlain:], buf.Bytes()[:buf.Len()-HeaderLenPlain])
	binary.LittleEndian.PutUint64(buf.Bytes()[:8], uint64(buf.Len()-HeaderLenPlain))
	_, writeErr := sf.c.Write(buf.Bytes())
	if writeErr != nil {
		sf.OnError(Error{NetworkErrorWrite, writeErr})
		sf.onClose()
	}
}

func (sf *Conn) onSecureSend(buf *bytes.Buffer) {
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
	sf.onPlainSend(buf)
}

func (sf *Conn) read(buffer *bytes.Buffer) {
	sf.mux.Lock()
	defer sf.mux.Unlock()
	sf.message.Data = buffer
	_, headerErr := io.ReadFull(sf.c, sf.message.Data.Bytes()[:8])
	if headerErr != nil {
		sf.OnError(Error{NetworkErrorHead, headerErr})
		sf.onClose()
		return
	}
	_ = binary.Read(bytes.NewBuffer(sf.message.Data.Bytes()[:8]),
		binary.LittleEndian, &sf.message.Length)
	if sf.message.Length > 4194304 {
		sf.message.Length = 4194304
	}
	n, bodyErr := sf.c.Read(sf.message.Data.Bytes()[:sf.message.Length])
	if bodyErr != nil {
		sf.OnError(Error{NetworkErrorHead, bodyErr})
		sf.onClose()
		return
	}
	fmt.Println("Total", n)
	fmt.Println(sf.message.Data.Bytes()[:n], string(sf.message.Data.Bytes()[:n]))
	sf.onMessage(sf.message)
}

type TServer struct {
	connId    atomic.Int64
	Addresses []Interface
	Listeners []*net.Listener
	Poller    netpoll.Poller
	RcvPool   *ConnPool
	SendPool  *ConnPool

	OnConnect    func(conn *Conn)
	OnDisconnect func(conn *Conn)
	Conns        map[int]*Conn
	CMux         sync.RWMutex
}

func NewTServer(interfaces []Interface) *TServer {
	sf := new(TServer)
	sf.Addresses = interfaces
	sf.Conns = map[int]*Conn{}
	sf.RcvPool = NewConnPool("read", 12, 24)
	sf.RcvPool.Run()
	sf.SendPool = NewConnPool("write", 12, 24)
	sf.SendPool.Run()
	sf.Poller, _ = netpoll.New(nil)
	return sf
}

func (sf *TServer) Listen() {
	for _, address := range sf.Addresses {
		listener, listenErr := net.Listen(address.Network, address.Address)
		if listenErr != nil {
			fmt.Println(listenErr)
			continue
		}
		sf.Listeners = append(sf.Listeners, &listener)
		go func() {
			for {
				con, acceptErr := listener.Accept()
				if acceptErr != nil {
					fmt.Println(acceptErr)
					break
				}
				sf.AcceptConn(con)
			}
		}()
	}
}

func (sf *TServer) AcceptConn(con net.Conn) {
	conn := NewConn(con, true)
	conn.Id = int(sf.connId.Add(1))
	sf.CMux.Lock()
	sf.Conns[conn.Id] = conn
	sf.CMux.Unlock()
	desc := netpoll.Must(netpoll.HandleRead(conn.c))
	conn.onClose = func() {
		_ = sf.Poller.Stop(desc)
		_ = conn.c.Close()
		sf.CMux.Lock()
		delete(sf.Conns, conn.Id)
		sf.CMux.Unlock()
		sf.OnDisconnect(conn)
		conn.OnDisconnect()
	}
	conn.Send = func(buf *bytes.Buffer) {
		conn.output <- buf
		sf.SendPool.JobQueue <- conn
	}
	pollError := sf.Poller.Start(desc, func(ev netpoll.Event) {
		if ev&netpoll.EventReadHup != 0 {
			conn.onClose()
			return
		}
		sf.RcvPool.JobQueue <- conn
	})
	if pollError != nil {
		conn.OnError(Error{NetworkErrorOpen, pollError})
		return
	}
	sf.OnConnect(conn)
	conn.OnConnect()
}

func (sf *TServer) Shutdown() {
	for _, listener := range sf.Listeners {
		v := *listener
		_ = v.Close()
	}
	sf.RcvPool.Stop()
	sf.SendPool.Stop()
}

func TestServer() {
	ts := NewTServer([]Interface{{"tcp4", "0.0.0.0:9000"}})
	ts.OnConnect = func(conn *Conn) {
		fmt.Println("On Connect ", conn)
		conn.OnMessage = func(netMsg *Message) {
			//fmt.Println(netMsg.Length, string(netMsg.Data.Bytes()[:netMsg.Length]))
			conn.Send(bytes.NewBuffer(netMsg.Data.Bytes()[:netMsg.Length]))
		}
		conn.OnError = func(err Error) {
			fmt.Println(fmt.Sprintf("conn error : %v %v\n", err.Type, err.Error()))
		}
		conn.OnConnect = func() {

		}
		conn.OnDisconnect = func() {

		}
	}
	ts.OnDisconnect = func(conn *Conn) {
		fmt.Println("On Disconnect ", conn)
	}
	ts.Listen()
	c := make(chan os.Signal)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	<-c
	ts.Shutdown()
}
