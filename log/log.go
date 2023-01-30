package log

import (
	"fmt"
	"os"
	"runtime"
	"time"
)

const (
	InfoColor      = "\033[1;34m%s\033[0m"
	NoticeColor    = "\033[1;36m%s\033[0m"
	WarningColor   = "\033[1;33m%s\033[0m"
	ErrorColor     = "\033[1;31m%s\033[0m"
	EmergencyColor = "\033[1;31m%s\033[0m"
	DebugColor     = "\033[0;36m%s\033[0m"
)

const (
	DEBUG     Level = 5
	INFO      Level = 4
	NOTICE    Level = 3
	WARN      Level = 2
	CRITICAL  Level = 1
	EMERGENCY Level = 0
)

var DefaultLogger *Logger

type Level int

func (l Level) String() string {
	switch l {
	case DEBUG:
		return "DEBUG"
	case INFO:
		return "INFO"
	case NOTICE:
		return "NOTICE"
	case WARN:
		return "WARN"
	case CRITICAL:
		return "CRITICAL"
	case EMERGENCY:
		{
			return "EMERGENCY"
		}
	default:
		return ""
	}
}

type Logger struct {
	file      *os.File
	exitChan  chan bool
	bufChan   chan []byte
	levelChan chan Level
	level     Level
	stopChan  chan bool
}

func NewLogger(level Level, fileName string) *Logger {
	l := &Logger{
		bufChan:   make(chan []byte, 200),
		levelChan: make(chan Level, 200),
		exitChan:  make(chan bool, 1),
		stopChan:  make(chan bool, 1),
		level:     level,
	}
	var err error
	l.file, err = os.OpenFile(fileName, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		l.FPrintln(CRITICAL, "log file not found : %s", fileName)
	}
	l.logTask()
	return l
}

func (l *Logger) SetLogLevel(level Level) {
	l.level = level
}

func (l *Logger) FPrintln(level Level, format string, v ...interface{}) {
	//if level > l.level {
	//	return
	//}
	select {
	case l.levelChan <- level:
		{
			//pc, fn, line, _ := runtime.Caller(2)
			//f := fmt.Sprintf("[%-24s][%-8s][%s:%s:%d] %s \n",
			//	time.Now().UTC().Format("2006-01-02T15:04:05.999Z"),
			//	level, runtime.FuncForPC(pc).Name(), fn, line, format)
			f := fmt.Sprintf("[%-22s][%-8s] %s \n",
				time.Now().Format("2006/01/02 15:04:05.99"),
				level, format)
			k := fmt.Sprintf(f, v...)
			l.bufChan <- []byte(k)
			//if level == EMERGENCY {
			//	panic(k)
			//}
		}
	default:
		return
	}
}

func (l *Logger) logTask() {
	go func() {
		runtime.LockOSThread()
		for {
			select {
			case msg := <-l.bufChan:
				{
					//_, _ = l.file.Write(msg)
					//_ = l.file.Sync()
					level := <-l.levelChan
					var d string
					switch level {
					case DEBUG:
						{
							d = fmt.Sprintf(DebugColor, string(msg))
						}
					case INFO:
						{
							d = fmt.Sprintf(InfoColor, string(msg))
						}
					case NOTICE:
						{
							d = fmt.Sprintf(NoticeColor, string(msg))
						}
					case WARN:
						{
							d = fmt.Sprintf(WarningColor, string(msg))
						}
					case CRITICAL:
						{
							d = fmt.Sprintf(ErrorColor, string(msg))
						}
					case EMERGENCY:
						{
							d = fmt.Sprintf(EmergencyColor, string(msg))
						}
					default:
						d = fmt.Sprintf(NoticeColor, string(msg))
					}
					fmt.Printf("%s", d)
				}
			case _ = <-l.exitChan:
				{
					if l.file != nil {
						_ = l.file.Close()
					}
					return
				}
			}
		}
	}()
}

func (l *Logger) Exit() {
	l.stopChan <- true
	for {
		if len(l.bufChan) == 0 {
			l.exitChan <- true
			return
		}
		time.Sleep(time.Millisecond * 200)
	}
}

func Log(level Level, format string, v ...interface{}) {
	DefaultLogger.FPrintln(level, format, v...)
}
