package app

import (
	"flag"
	"fmt"
	"github.com/joho/godotenv"
	. "github.com/updatedennismwangi/log"
	. "github.com/updatedennismwangi/runtime"
	. "github.com/updatedennismwangi/utils"
	"os"
	"time"
)

type Application interface {
	Install()
	Shutdown()
}

var GAPP *GApp

type GApp struct {
	Apps      map[string]func(runtime *Runtime) Application
	StartHook func()
	StopHook  func()
}

func (sf *GApp) Register(name string, fn func(runtime *Runtime) Application) {
	sf.Apps[name] = fn
}

func (sf *GApp) Run(pidDir string, logDir string, envDir string) {
	if len(envDir) > 0 {
		_ = godotenv.Load(envDir)
	}
	runTime := NewRuntime(pidDir)
	var app string
	f := flag.NewFlagSet("main", flag.ContinueOnError)
	f.StringVar(&app, "app", "main", "Provider service to run")
	args := os.Args
	if len(args) > 1 {
		_ = f.Parse(os.Args[1:2])
	}
	err := runTime.CheckRunning(app)
	if err != nil {
		DefaultLogger = NewLogger(DEBUG, fmt.Sprintf("%s/error.log", logDir))
		Log(CRITICAL, "Application : %s [error=%v]", app, err)
		DefaultLogger.Exit()
		return
	}
	DefaultLogger = NewLogger(DEBUG, fmt.Sprintf("%s/%s.log", logDir, app))
	Log(INFO, "Bootstrap : Starting application name : %s | pid : %d | start : %s",
		runTime.AppName, runTime.PID, runTime.StartTime.Format(ISO8601))
	defer func() {
		Log(INFO, "Bootstrap : Stopping application name : %s | pid : %d | stop : %s | uptime : %s",
			runTime.AppName, runTime.PID, time.Now().Format(ISO8601), runTime.Uptime())
		DefaultLogger.Exit()
		runTime.StopRunning()
	}()
	newApp, ok := sf.Apps[app]
	if ok {
		application := newApp(runTime)
		runTime.Shutdown(application.Shutdown)
		Log(INFO, "CloseHandler : SIGINT configured to clean shutdown")
		sf.StartHook()
		defer sf.StopHook()
		application.Install()
		runTime.Wt.Wait()
	}
}

func init() {
	GAPP = &GApp{Apps: map[string]func(runtime *Runtime) Application{}}
}
