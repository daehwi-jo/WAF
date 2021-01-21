// +build linux

package main

import "syscall"
import "fmt"
import "os"

func main() {

	var proc_attr syscall.ProcAttr
	var sys_attr syscall.SysProcAttr

	len := len(os.Args)
	fmt.Println("arg len ", len, "bin", os.Args[0])
	if os.Args[len-1] == "&" {
		sub_main()
		return
	}

	sys_attr.Foreground = false
	proc_attr.Sys = &sys_attr
	proc_attr.Files = []uintptr{uintptr(syscall.Stdin), uintptr(syscall.Stdout), uintptr(syscall.Stderr)}

	args := make([]string, len+1)
	copy(args, os.Args[:])
	args[len] = "&"
	pid, err := syscall.ForkExec(os.Args[0], args, &proc_attr)
	if err != nil {
		fmt.Println("FORK ERROR (%s)", err)
		return
	}

	if pid != 0 {
		//	fmt.Println("pid return  (%d)", pid)
		return
	}
}
