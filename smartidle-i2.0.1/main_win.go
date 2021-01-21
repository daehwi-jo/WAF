// +build !linux

package main

import (
	"fmt"
	_ "os"
	"time"

	"golang.org/x/sys/windows/svc"
)

type ddnsAgentService struct {
}

// service handler
func (srv *ddnsAgentService) Execute(args []string, req <-chan svc.ChangeRequest, stat chan<- svc.Status) (svcSpecificEC bool, exitCode uint32) {
	stat <- svc.Status{State: svc.StartPending}

	// 실제 서비스 내용
	//stopChan := make(chan int, 1)

	// network wating in charlie
	//go cls.Cls_startsvc(cls.App_data(app_main), stopChan)
	//go cls.Http_startsvc
	go sub_main()

	stat <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}

LOOP:
	for {
		// 서비스 변경 요청에 대해 핸들링
		switch r := <-req; r.Cmd {
		case svc.Stop, svc.Shutdown:
			break LOOP
		case svc.Interrogate:
			stat <- r.CurrentStatus
		case svc.Pause:
			break LOOP
		case svc.Continue:
			break LOOP
		}
		time.Sleep(100 * time.Millisecond)
	}

	stat <- svc.Status{State: svc.StopPending}
	return
}

func main() {

	/*
		if (len(os.Args) > 3 && os.Args[len(os.Args)-1] == "-F") || len(os.Args) == 1 {
			ch := make(chan int)
			go sub_main2(ch)

			for {
				select {
				case msg := <-ch:
					if msg == 1 {
						close(ch)
						return
					}
				default:
					time.Sleep(1 * time.Second)
				}

			}

			return
		}

	*/

	// for windows service
	err := svc.Run("ddnsAgent", &ddnsAgentService{})

	if err != nil {
		fmt.Println(err.Error())
		return
	}

}
