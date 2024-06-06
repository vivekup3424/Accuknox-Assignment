package main

import (
	"bufio"
	"errors"
	"flag"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

// Function to convert a string to a fixed-size byte array
func strToCharArr(s string) [16]byte {
	var arr [16]byte
	copy(arr[:], s)
	return arr
}

func main() {
	var portNum uint
	var processName string

	// Parse command-line arguments
	flag.UintVar(&portNum, "port", 4040, "TCP port number to filter")
	flag.StringVar(&processName, "process", "go", "Process name to filter")
	flag.Parse()

	// Remove memory limit for eBPF
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("Failed to set rlimit: %v", err)
	}

	// Load eBPF objects
	objs := packetFilterObjects{}
	if err := loadPacketFilterObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %s", err)
	}
	defer objs.Close()

	// Update maps with provided port number and process name
	updateMaps(objs, portNum, processName)

	// Attach the eBPF program to the cgroup
	cgroupPath, err := detectCgroupPath()
	if err != nil {
		log.Fatalf("detecting cgroup path: %v", err)
	}

	l, err := link.AttachCgroup(link.CgroupOptions{
		Path:    cgroupPath,
		Attach:  ebpf.AttachCGroupInetIngress,
		Program: objs.BlockProcessPorts,
	})
	if err != nil {
		log.Fatalf("could not attach cgroup program: %s", err)
	}
	defer l.Close()

	log.Printf("Attached cgroup program to %s", cgroupPath)
	log.Printf("Press Ctrl-C to exit and remove the program")

	handleSignals(objs)
}

// updateMaps updates the port and process name maps with the provided values
func updateMaps(objs packetFilterObjects, portNum uint, processName string) {
	portKey := uint32(0)
	portValue := uint32(portNum)
	if err := objs.PortMap.Update(portKey, portValue, ebpf.UpdateAny); err != nil {
		log.Fatalf("updating port map: %v", err)
	}

	processKey := uint32(0)
	processValue := strToCharArr(processName)
	if err := objs.ProcessNameMap.Update(processKey, processValue, ebpf.UpdateAny); err != nil {
		log.Fatalf("updating process name map: %v", err)
	}
}

// handleSignals handles OS signals to gracefully shut down
func handleSignals(objs packetFilterObjects) {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)

	for {
		select {
		case <-ticker.C:
			printDropCount(objs)
		case <-stop:
			log.Println("Received signal, exiting...")
			return
		}
	}
}

// printDropCount prints the drop count from the drop_counter map
func printDropCount(objs packetFilterObjects) {
	key := uint32(0)
	var dropCount uint64
	if err := objs.DropCounter.Lookup(key, &dropCount); err != nil {
		log.Printf("Error reading drop counter: %v", err)
		return
	}
	log.Printf("Dropped %d packets", dropCount)
}

// detectCgroupPath returns the first-found mount point of type cgroup2
func detectCgroupPath() (string, error) {
	f, err := os.Open("/proc/mounts")
	if err != nil {
		return "", err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		fields := strings.Split(scanner.Text(), " ")
		if len(fields) >= 3 && fields[2] == "cgroup2" {
			return fields[1], nil
		}
	}

	return "", errors.New("cgroup2 not mounted")
}
