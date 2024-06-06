package main

import (
	"flag"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

// accept flags for the interface name and port number,
// and to log dropped packet count periodically
func main() {
	var ifaceName string
	var portNum uint

	//getting the interface name, and port number from commandline
	flag.StringVar(&ifaceName, "iface", "wlp0s20f3",
		"Network interface to attach to")
	flag.UintVar(&portNum, "port", 4040, "TCP port number to filter")

	flag.Parse()
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("Failed to set rlimit: %v", err)
	}

	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		log.Fatalf("lookup network iface %q: %s", ifaceName, err)
	}

	//load pre-compiled program onto the kernel
	objs := portPacketFilterObjects{}
	if err := loadPortPacketFilterObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %s", err)
	}
	defer objs.Close()

	//update the object map
	portKey := uint32(0)
	portValue := uint32(portNum)
	if err := objs.PortMap.Update(portKey, portValue, ebpf.UpdateAny); err != nil {
		log.Fatalf("updating port map: %v", err)
	}
	//Attach or link the program
	l, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.XdpFilterFunc,
		Interface: iface.Index,
	})

	if err != nil {
		log.Fatalf("could not attach XDP program: %s", err)
	}
	defer l.Close()

	log.Printf("Attached XDP program to iface %q (index %d)", iface.Name, iface.Index)
	log.Printf("Press Ctrl-C to exit and remove the program")

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

func printDropCount(objs portPacketFilterObjects) {
	key := uint32(0)
	var dropCount uint64
	if err := objs.DropCounter.Lookup(key, &dropCount); err != nil {
		log.Printf("Error reading drop counter: %v", err)
		return
	}
	log.Printf("Dropped %d packets", dropCount)
}

package main

import (
	"flag"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

// accept flags for the interface name and port number,
// and to log dropped packet count periodically
func main() {
	var ifaceName string
	var portNum uint

	//getting the interface name, and port number from commandline
	flag.StringVar(&ifaceName, "iface", "wlp0s20f3",
		"Network interface to attach to")
	flag.UintVar(&portNum, "port", 4040, "TCP port number to filter")

	flag.Parse()
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("Failed to set rlimit: %v", err)
	}

	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		log.Fatalf("lookup network iface %q: %s", ifaceName, err)
	}

	//load pre-compiled program onto the kernel
	objs := portPacketFilterObjects{}
	if err := loadPortPacketFilterObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %s", err)
	}
	defer objs.Close()

	//update the object map
	portKey := uint32(0)
	portValue := uint32(portNum)
	if err := objs.PortMap.Update(portKey, portValue, ebpf.UpdateAny); err != nil {
		log.Fatalf("updating port map: %v", err)
	}
	//Attach or link the program
	l, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.XdpFilterFunc,
		Interface: iface.Index,
	})

	if err != nil {
		log.Fatalf("could not attach XDP program: %s", err)
	}
	defer l.Close()

	log.Printf("Attached XDP program to iface %q (index %d)", iface.Name, iface.Index)
	log.Printf("Press Ctrl-C to exit and remove the program")

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

func printDropCount(objs portPacketFilterObjects) {
	key := uint32(0)
	var dropCount uint64
	if err := objs.DropCounter.Lookup(key, &dropCount); err != nil {
		log.Printf("Error reading drop counter: %v", err)
		return
	}
	log.Printf("Dropped %d packets", dropCount)
}
