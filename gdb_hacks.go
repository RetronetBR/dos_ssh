package main

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"io"
	"log"
	"net"
	"strings"
	"sync"
	"time"
)

var gfb []byte
var lastFramebuffer []byte
var UpdateScreenNow chan bool
var Pulling sync.Mutex
var FrameBufferMu sync.RWMutex
var gdbReader *bufio.Reader

func StartPollingGDB() {
	UpdateScreenNow = make(chan bool)
	gfb = make([]byte, 0)
	log.Println("Connecting to local GDB stub on 127.0.0.1:1234")
	nic, err := net.Dial("tcp", "localhost:1234")
	LazyHandle(err)
	log.Println("GDB connection ready")
	gdbReader = bufio.NewReader(nic)
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			Poll(nic)
		case <-UpdateScreenNow:
			Poll(nic)
		}
	}
}

func Poll(nic net.Conn) {
	Pulling.Lock()
	defer Pulling.Unlock()

	// RSP commands that inspect memory only work while the guest is stopped.
	// Ctrl-C interrupts it; after the snapshot, "c" resumes execution.
	InterruptTarget(nic)
	for i := 0; i < 2; i++ {
		if i == 0 {
			SendCMD(nic, "$mb8000,800#5b") // BIOS Framebuffer ranges
		} else {
			SendCMD(nic, "$mb8800,7a0#93") // BIOS Framebuffer ranges
		}
	}
	ContinueTarget(nic)
}

func InterruptTarget(nic net.Conn) {
	_, err := nic.Write([]byte{0x03})
	LazyHandle(err)
	_ = nic.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	_, err = readGDBPacket()
	if err != nil {
		if timeout, ok := err.(net.Error); !ok || !timeout.Timeout() {
			LazyHandle(err)
		}

		// A target left stopped by an earlier client does not answer another
		// interrupt. Querying the stop reason confirms that state.
		_ = nic.SetReadDeadline(time.Time{})
		_, err = nic.Write([]byte("$?#3f"))
		LazyHandle(err)
		_, err = readGDBPacket()
		LazyHandle(err)
	}
	_ = nic.SetReadDeadline(time.Time{})
	_, err = nic.Write([]byte("+"))
	LazyHandle(err)
}

func ContinueTarget(nic net.Conn) {
	// A continue command has no response until the target stops again. Reading
	// a packet here would therefore block the polling loop.
	_, err := nic.Write([]byte("$c#63"))
	LazyHandle(err)
}

func LazyHandle(err error) {
	if err != nil {
		log.Fatalln(err.Error())
	}
}

func LatestFramebuffer() []byte {
	FrameBufferMu.RLock()
	defer FrameBufferMu.RUnlock()

	if len(lastFramebuffer) == 0 {
		return nil
	}

	return append([]byte(nil), lastFramebuffer...)
}

func SendCMD(nic net.Conn, payload string) {
	_, err := nic.Write([]byte(payload))
	LazyHandle(err)
	reply, err := readGDBPacket()
	LazyHandle(err)

	if len(reply) > 1000 {
		printtext(reply)
	}

	_, err = nic.Write([]byte("+"))
	LazyHandle(err)
}

var fbcount int = 0

func readGDBPacket() ([]byte, error) {
	for {
		b, err := gdbReader.ReadByte()
		if err != nil {
			return nil, err
		}
		if b == '$' {
			break
		}
	}

	payload := make([]byte, 0, 4096)
	for {
		b, err := gdbReader.ReadByte()
		if err != nil {
			return nil, err
		}
		if b == '#' {
			break
		}
		payload = append(payload, b)
	}

	var checksum [2]byte
	if _, err := io.ReadFull(gdbReader, checksum[:]); err != nil {
		return nil, err
	}
	return payload, nil
}

func printtext(dump []byte) {
	GDBSplit := strings.Split(string(dump), "#")
	bin, err := hex.DecodeString(string(GDBSplit[0]))
	if err == nil {
		for i := 0; i < len(bin); i++ {
			gfb = append(gfb, bin[i])
		}
	}
	fbcount++
	if fbcount == 2 {
		fbcount = 0
		snapshot := append([]byte(nil), gfb...)
		FrameBufferMu.Lock()
		changed := !bytes.Equal(lastFramebuffer, snapshot)
		lastFramebuffer = snapshot
		FrameBufferMu.Unlock()
		if changed {
			FrameBufferUpdate <- snapshot
		}
		gfb = []byte{}
	}
}
