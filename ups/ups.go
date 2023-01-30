package ups

import (
	nut "github.com/robbiet480/go.nut"
	. "github.com/updatedennismwangi/log"
	"time"
)

type UPS struct {
	Client    *nut.Client
	ExitChan  chan bool
	CloseChan chan bool
}

func NewUPS() *UPS {
	ups := new(UPS)
	client, connectErr := nut.Connect("127.0.0.1")
	if connectErr != nil {
		Log(WARN, "Ups connection module not available")
	} else {
		Log(INFO, "Ups management module active")
		ups.Client = &client
		ups.CloseChan = make(chan bool, 1)
		ups.ExitChan = make(chan bool, 1)
		ups.ListenTask()
	}
	return ups
}

func (sf *UPS) ListenTask() {
	go func() {
		var batteryCharge int64
		var status string
		upsG, err := sf.Client.GetUPSList() // TODO :: Fix blocking bug in go 1.9
		var ups *nut.UPS
		if err == nil {
			ups = &upsG[0]
		}
		t := time.NewTicker(time.Second * 2)
	outer:
		for {
			select {
			case <-t.C:
				{
					v, _ := ups.GetVariables()
					for _, v := range v {
						switch v.Name {
						case "battery.charge":
							{
								batteryCharge = v.Value.(int64)
							}
						case "ups.status":
							{
								status = v.Value.(string)
							}
						}
					}
					if status == "OB" {
						Log(WARN, "Power : %s %d", status, batteryCharge)
					}
				}
			case <-sf.CloseChan:
				{
					break outer
				}
			}
		}
		_, err = sf.Client.Disconnect()
		sf.ExitChan <- true
	}()
}

func (sf *UPS) Exit() {
	if sf.Client != nil {
		sf.CloseChan <- true
		<-sf.ExitChan
	}
}
