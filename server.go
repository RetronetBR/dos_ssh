package main

import (
	"golang.org/x/crypto/ssh"
	"log"
	"net"
	"sync"
	"time"
)

var Keyin chan string // Used to take keys from connections into the VNC connection
var SubscribersMu sync.RWMutex

func main() {
	// Setup the chans
	FrameBufferUpdate = make(chan []byte)
	Keyin = make(chan string, 100)
	FrameBufferSubscribers = make(map[string]chan []byte)

	// Start the hub that broadcasts framebuffer updates
	go MessageHub(FrameBufferUpdate, FrameBufferSubscribers)

	log.Println("Starting GDB client")
	go StartPollingGDB()
	log.Println("Starting VNC client")
	go VNCKeyIn(Keyin)
	log.Println("Starting SSH server")
	StartSSH()
}

func ServeDOSTerm(channel ssh.Channel) {
	log.Println("Starting DOS terminal session")
	go ReadSSHIn(channel)
	MyID := randSeq(5)
	FBIN := make(chan []byte)
	SubscribersMu.Lock()
	FrameBufferSubscribers[MyID] = FBIN
	SubscribersMu.Unlock()
	defer func() {
		SubscribersMu.Lock()
		delete(FrameBufferSubscribers, MyID)
		SubscribersMu.Unlock()
	}() // Unsubscribe when dead
	log.Printf("Subscribed framebuffer stream %s", MyID)
	FB := make([]byte, 0)
	for {
		FB = <-FBIN
		if len(FB) != 4000 {
			log.Printf("Skipping framebuffer update %s: len=%d", MyID, len(FB))
			continue
		}
		_, _ = channel.Write([]byte("\x1B[0;0H"))
		outbound := ""

		ptr := 0
		column := 0
		for ptr < len(FB) {
			outbound = outbound + VESAtoVT100(FB[ptr+1])
			outbound = outbound + CorrectBadChars(FB[ptr])

			ptr = ptr + 2
			column++
			if column == 80 && ptr < len(FB) {
				// DOS is 80 columns wide. Clear any stale content left in a
				// wider SSH terminal before moving to the next row.
				outbound += "\x1B[K\r\n"
				column = 0
			}
		}
		outbound += "\x1B[K\x1B[J"
		_, err := channel.Write([]byte(outbound))
		if err != nil {
			log.Printf("Terminal write failed for %s: %v", MyID, err)
			return
		}
	}
}

func ReadSSHIn(channel ssh.Channel) {
	buffer := make([]byte, 2)
	for {
		n, err := channel.Read(buffer)
		if err != nil {
			log.Printf("SSH read ended: %v", err)
			return
		}

		if n > 0 {
			log.Printf("SSH input bytes received: %q", string(buffer[:n]))
			for i := 0; i < n; i++ {
				Keyin <- string(buffer[i])
			}
		}
	}
}

func VNCKeyIn(Presses chan string) {
	log.Println("Connecting to local VNC on 127.0.0.1:5900")
	vncnic, err := net.Dial("tcp", "localhost:5900")
	LazyHandle(err)

	vncconn, err := NewVNCClient(vncnic)
	LazyHandle(err)
	log.Println("VNC connection ready")

	for in := range Presses {
		log.Printf("Forwarding SSH input to VNC: %q", in)
		Pulling.Lock()
		for i := 0; i < len(in); i++ {
			if key, ok := controlByteToVNCKey(in[i]); ok {
				log.Printf("VNC control chord: Ctrl+%c", key)
				LazyHandle(vncconn.KeyEvent(0xFFE3, true)) // Control_L down
				LazyHandle(vncconn.KeyEvent(key, true))
				LazyHandle(vncconn.KeyEvent(key, false))
				LazyHandle(vncconn.KeyEvent(0xFFE3, false)) // Control_L up
				continue
			}
			key, ok := sshByteToVNCKey(in[i])
			if !ok {
				log.Printf("Ignoring control byte: 0x%02x", in[i])
				continue
			}
			log.Printf("VNC KeyEvent down key=0x%04x", key)
			LazyHandle(vncconn.KeyEvent(key, true))
			log.Printf("VNC KeyEvent up key=0x%04x", key)
			LazyHandle(vncconn.KeyEvent(key, false))
		}
		time.Sleep(time.Millisecond * 25)
		Pulling.Unlock()
	}
}

func controlByteToVNCKey(b byte) (uint32, bool) {
	// These C0 bytes have dedicated keysyms and are handled separately.
	if b == '\t' || b == '\n' || b == '\r' {
		return 0, false
	}
	if b >= 1 && b <= 26 {
		return uint32('a' + b - 1), true
	}
	if b >= 0x1c && b <= 0x1f {
		return uint32(b + 0x40), true
	}
	return 0, false
}

func sshByteToVNCKey(b byte) (uint32, bool) {
	switch b {
	case '\r', '\n':
		return 0xFF0D, true
	case 0x7f, 0x08:
		return 0xFF08, true
	case '\t':
		return 0xFF09, true
	case 0x1b:
		return 0xFF1B, true
	}
	if b < 0x20 {
		return 0, false
	}
	return uint32(b), true
}
