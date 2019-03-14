// Copyright 2019 The Decred developers. All rights reserved.
// Copyright 2016 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Program dcrps is a tool to list currently running Decred Go processes.
package main

import (
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"

	"github.com/google/gops/goprocess"
	"github.com/shirou/gopsutil/process"
	"github.com/xlab/treeprint"
)

var nameToPid = map[string]int{}

func init() {
	ps := goprocess.FindAll()
	for _, p := range ps {
		if !strings.HasPrefix(p.Exec, dcrPrefix) {
			continue
		}
		_, found := nameToPid[p.Exec]
		if found {
			nameToPid[p.Exec] = -1 // multiple procs with this name
		} else {
			nameToPid[p.Exec] = p.PID
		}
	}
}

const (
	dcrPrefix = "dcr"

	helpText = `dcrps is a tool to list and diagnose Decred Go processes.

dcrps <"help"|"tree">
dcrps <cmd> <exec|pid|addr> ...
dcrps <exec|pid> # displays process info

Commands with no argument:
    help        Displays this message.
    tree        Displays process tree.

Commands with <exec|pid|addr> argument:
    stack       Prints the stack trace.
    gc          Runs the garbage collector and blocks until successful.
    setgc	    Sets the garbage collection target percentage.
    memstats    Prints the allocation and garbage collection stats.
    version     Prints the Go version used to build the program.
    stats       Prints the vital runtime stats.
    trace       Runs the runtime tracer for 5 secs and launches "go tool trace".
    pprof-heap  Reads the heap profile and launches "go tool pprof".
    pprof-cpu   Reads the CPU profile and launches "go tool pprof".

All commands with a <exec|pid|addr> argument require the agent running on the Go
process. The symbol "*" next to the process name indicates the process runs the
agent.`
)

func main() {
	if len(os.Args) < 2 {
		processes()
		return
	}

	cmd := os.Args[1]

	// See if it is a PID.
	pid, err := strconv.Atoi(cmd)
	if err == nil {
		processInfo(pid)
		return
	}

	if cmd == "help" {
		usage("")
	}

	if cmd == "tree" {
		displayProcessTree()
		return
	}

	fn, ok := cmds[cmd]
	if !ok {
		pid, ok := nameToPid[cmd]
		if ok {
			processInfo(pid)
			return
		}
		usage("unknown subcommand")
	}
	if len(os.Args) < 3 {
		usage("Missing PID or address.")
		os.Exit(1)
	}

	addr, err := targetToAddr(os.Args[2])
	if err != nil {
		fmt.Fprintf(os.Stderr, "Couldn't resolve addr or pid %v to TCPAddress: %v\n",
			os.Args[2], err)
		os.Exit(1)
	}

	var params []string
	if len(os.Args) > 3 {
		params = append(params, os.Args[3:]...)
	}
	if err := fn(*addr, params); err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
}

func processes() {
	ps := goprocess.FindAll()
	var dcrPs []goprocess.P
	for i := range ps {
		if strings.HasPrefix(ps[i].Exec, dcrPrefix) {
			dcrPs = append(dcrPs, ps[i])
		}
	}

	max := func(i, j int) int {
		if i > j {
			return i
		}
		return j
	}

	var maxPID, maxPPID, maxExec, maxVersion int
	for _, p := range dcrPs {
		maxPID = max(maxPID, len(strconv.Itoa(p.PID)))
		maxPPID = max(maxPPID, len(strconv.Itoa(p.PPID)))
		maxExec = max(maxExec, len(p.Exec))
		maxVersion = max(maxVersion, len(p.BuildVersion))
	}

	fmtString := "%" + strconv.Itoa(maxPID) + "d %" + strconv.Itoa(maxPPID) + "d" +
		" %" + strconv.Itoa(maxExec) + "s %1s %" + strconv.Itoa(maxVersion) + "s %s\n"

	for _, p := range dcrPs {
		agentStar := " "
		if p.Agent {
			agentStar = "*"
		}

		fmt.Printf(fmtString, p.PID, p.PPID, p.Exec, agentStar, p.BuildVersion, p.Path)
	}
}

func processInfo(pid int) {
	p, err := process.NewProcess(int32(pid))
	if err != nil {
		log.Fatalf("Cannot read process info: %v", err)
	}
	if v, err := p.Parent(); err == nil {
		fmt.Printf("parent PID:\t%v\n", v.Pid)
	}
	if v, err := p.NumThreads(); err == nil {
		fmt.Printf("threads:\t%v\n", v)
	}
	if v, err := p.MemoryPercent(); err == nil {
		fmt.Printf("memory usage:\t%.3f%%\n", v)
	}
	if v, err := p.CPUPercent(); err == nil {
		fmt.Printf("cpu usage:\t%.3f%%\n", v)
	}
	if v, err := p.Username(); err == nil {
		fmt.Printf("username:\t%v\n", v)
	}
	if v, err := p.Cmdline(); err == nil {
		fmt.Printf("cmd+args:\t%v\n", v)
	}
	if v, err := p.Connections(); err == nil {
		if len(v) > 0 {
			for _, conn := range v {
				fmt.Printf("local/remote:\t%v:%v <-> %v:%v (%v)\n",
					conn.Laddr.IP, conn.Laddr.Port, conn.Raddr.IP, conn.Raddr.Port, conn.Status)
			}
		}
	}
}

// pstree contains a mapping between the PPIDs and the child processes.
var pstree map[int][]goprocess.P

// displayProcessTree displays a tree of all the running Go processes.
func displayProcessTree() {
	ps := goprocess.FindAll()
	pstree = make(map[int][]goprocess.P)
	for _, p := range ps {
		if !strings.HasPrefix(p.Exec, dcrPrefix) {
			continue
		}
		pstree[p.PPID] = append(pstree[p.PPID], p)
	}
	tree := treeprint.New()
	tree.SetValue("...")
	seen := map[int]bool{}
	for _, p := range ps {
		if !strings.HasPrefix(p.Exec, dcrPrefix) {
			continue
		}
		constructProcessTree(p.PPID, p, seen, tree)
	}
	fmt.Println(tree.String())
}

// constructProcessTree constructs the process tree in a depth-first fashion.
func constructProcessTree(ppid int, process goprocess.P, seen map[int]bool, tree treeprint.Tree) {
	if seen[ppid] {
		return
	}
	seen[ppid] = true
	if ppid != process.PPID {
		output := strconv.Itoa(ppid) + " (" + process.Exec + ")" + " {" + process.BuildVersion + "}"
		if process.Agent {
			tree = tree.AddMetaBranch("*", output)
		} else {
			tree = tree.AddBranch(output)
		}
	} else {
		tree = tree.AddBranch(ppid)
	}
	for index := range pstree[ppid] {
		process := pstree[ppid][index]
		constructProcessTree(process.PID, process, seen, tree)
	}
}

func usage(msg string) {
	if msg != "" {
		fmt.Printf("dcrps: %v\n", msg)
	}
	fmt.Fprintf(os.Stderr, "%v\n", helpText)
	os.Exit(1)
}
