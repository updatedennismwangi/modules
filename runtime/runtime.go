package runtime

import (
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"sync"
	"syscall"
	"time"
)

// A Runtime holds the program current execution stats
type Runtime struct {
	AppName   string
	PID       int       // Current processId
	StartTime time.Time // Boot time
	PidDir    string
	Wt        sync.WaitGroup
}

// NewRuntime creates a new instance and bootstraps startTime and PID
func NewRuntime(pidDir string) *Runtime {
	vrt := new(Runtime)
	vrt.PID = os.Getpid()
	vrt.StartTime = time.Now()
	vrt.PidDir = pidDir
	return vrt
}

// Uptime returns the time the service has been online as a string
func (rt *Runtime) Uptime() string {
	duration := time.Since(rt.StartTime)
	return fmt.Sprintf("%02dd %02dh %02dm %02ds", int(duration.Hours()/24), int(duration.Hours())%24, int(duration.Minutes())%60, int(duration.Seconds())%60)
}

func (rt *Runtime) CheckRunning(appName string) error {
	rt.AppName = appName
	fmt.Println(fmt.Sprintf("%s/%s", rt.PidDir, rt.AppName), rt.PID)
	return rt.WritePidFile(fmt.Sprintf("%s/%s", rt.PidDir, rt.AppName), rt.PID)
}

func (rt *Runtime) StopRunning() {
	rt.RemovePidFile(fmt.Sprintf("%s/%s", rt.PidDir, rt.AppName))
}

func (rt *Runtime) Shutdown(shutdown func()) {
	rt.Wt.Add(1)
	c := make(chan os.Signal)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-c
		shutdown()
		rt.Wt.Done()
	}()
}

// WritePidFile writes a given processId(pid) to a given file path.
func (rt *Runtime) WritePidFile(pidFile string, pid int) error {
	// Read in the pid file as a slice of bytes.
	if pidData, err := os.ReadFile(pidFile); err == nil {
		// Convert the file contents to an integer.
		if pid, err := strconv.Atoi(string(pidData)); err == nil {
			// Look for the pid in the process list.
			if process, err := os.FindProcess(pid); err == nil {
				// SendCompressed the process a signal zero kill.
				if err := process.Signal(syscall.Signal(0)); err == nil {
					// We only get an error if the pid isn't running, or it's not ours.
					return fmt.Errorf("pid already running: %d", pid)
				}
			}
		}
	}
	// If we get here, then the pidfile didn't exist,
	// or the pid in it doesn't belong to the user running this app.
	return os.WriteFile(pidFile, []byte(fmt.Sprintf("%d", pid)), 0664)
}

// RemovePidFile deletes from disk the given file path.
func (rt *Runtime) RemovePidFile(pidFile string) {
	_ = os.Remove(pidFile)
}
