package pool

import (
	"sync"
)

// Job represents the job to be run

type Job interface {
	ProcessPool(worker *Worker)
}

// Worker represents the worker that executes the job
type Worker struct {
	WorkerId   int
	WorkerPool chan chan Job
	JobChannel chan Job
	quit       chan bool
}

func NewWorker(workerPool chan chan Job, workerId int) Worker {
	return Worker{
		WorkerId:   workerId,
		WorkerPool: workerPool,
		JobChannel: make(chan Job),
		quit:       make(chan bool)}
}

// Start method starts the run loop for the worker, listening for a quit channel in
// case we need to stop it
func (w Worker) Start() {
	// Log(INFO,"Worker task :: %d", w.WorkerId)
	go func() {
		for {
			// register the current worker into the worker queue.
			w.WorkerPool <- w.JobChannel
			select {
			case job := <-w.JobChannel:
				// Log(INFO,"Worker task %d Processing Channel task %v", w.WorkerId, job)
				job.ProcessPool(&w)
			case <-w.quit:
				// we have received a signal to stop
				// Log(INFO,"Worker task killed %d", w.WorkerId)
				return
			}
		}
	}()
}

// Stop signals the worker to stop listening for work requests.
func (w Worker) Stop() {
	go func() {
		w.quit <- true
	}()
}

type Dispatcher struct {
	// A pool of workers channels that are registered with the dispatcher
	Name       string
	WorkerPool chan chan Job
	MaxWorkers int
	MaxQueue   int
	JobQueue   chan Job
	Workers    []Worker
	Wt         *sync.WaitGroup
}

func NewDispatcher(name string, maxWorkers int, maxQueue int) *Dispatcher {
	d := &Dispatcher{Name: name, MaxWorkers: maxWorkers, MaxQueue: maxQueue}
	d.WorkerPool = make(chan chan Job, d.MaxWorkers)
	d.JobQueue = make(chan Job, maxQueue)
	d.Workers = []Worker{}
	return d
}

func (d *Dispatcher) Run() {
	// starting n number of workers
	for i := 0; i < d.MaxWorkers; i++ {
		worker := NewWorker(d.WorkerPool, i)
		d.Workers = append(d.Workers, worker)
		worker.Start()
	}
	go d.dispatch()
}

func (d *Dispatcher) Stop() {
	for _, worker := range d.Workers {
		worker.Stop()
	}
}

func (d *Dispatcher) dispatch() {
	for {
		select {
		case job := <-d.JobQueue:
			// a job request has been received
			go func(job Job) {
				// try to obtain a worker job channel that is available.
				// this will block until a worker is idle
				jobChannel := <-d.WorkerPool
				// dispatch the job to the worker job channel
				jobChannel <- job
			}(job)
		}
	}
}
