package main

import (
	"golang.org/x/crypto/ssh"
	"log"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

var Keyin chan string // Used to take keys from connections into the VNC connection
var SubscribersMu sync.RWMutex

const (
	vncKeyBackSpace = 0xFF08
	vncKeyTab       = 0xFF09
	vncKeyReturn    = 0xFF0D
	vncKeyEscape    = 0xFF1B
	vncKeyHome      = 0xFF50
	vncKeyLeft      = 0xFF51
	vncKeyUp        = 0xFF52
	vncKeyRight     = 0xFF53
	vncKeyDown      = 0xFF54
	vncKeyPageUp    = 0xFF55
	vncKeyPageDown  = 0xFF56
	vncKeyEnd       = 0xFF57
	vncKeyInsert    = 0xFF63
	vncKeyDelete    = 0xFFFF
	vncKeyShiftL    = 0xFFE1
	vncKeyControlL  = 0xFFE3
	vncKeyAltL      = 0xFFE9
)

type VNCKeyStroke struct {
	Key       uint32
	Modifiers []uint32
}

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
	buffer := make([]byte, 128)
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
	vncconn := connectVNCWithRetry()

	var (
		pending []byte
		flushCh <-chan time.Time
	)

	for {
		select {
		case in, ok := <-Presses:
			if !ok {
				return
			}
			log.Printf("SSH input bytes received: %q", in)
			pending = append(pending, []byte(in)...)
			vncconn, pending = flushPendingKeys(vncconn, pending, false)
			if len(pending) > 0 {
				flushCh = time.After(25 * time.Millisecond)
			} else {
				flushCh = nil
			}
		case <-flushCh:
			vncconn, pending = flushPendingKeys(vncconn, pending, true)
			flushCh = nil
		}
	}
}

func flushPendingKeys(vncconn *VNCClient, pending []byte, force bool) (*VNCClient, []byte) {
	strokes, rest := parseSSHKeyStream(pending, force)
	if len(strokes) == 0 {
		return vncconn, rest
	}

	Pulling.Lock()
	defer Pulling.Unlock()
	for _, stroke := range strokes {
		log.Printf("Forwarding SSH keystroke to VNC: key=0x%04x modifiers=%v", stroke.Key, stroke.Modifiers)
		if err := sendVNCKeyStroke(vncconn, stroke); err != nil {
			log.Printf("VNC send failed, reconnecting: %v", err)
			if vncconn.conn != nil {
				_ = vncconn.conn.Close()
			}
			vncconn = connectVNCWithRetry()
			if err := sendVNCKeyStroke(vncconn, stroke); err != nil {
				log.Printf("VNC send failed after reconnect: %v", err)
				continue
			}
		}
	}
	time.Sleep(25 * time.Millisecond)
	return vncconn, rest
}

func connectVNCWithRetry() *VNCClient {
	for {
		log.Println("Connecting to local VNC on 127.0.0.1:5900")
		vncnic, err := net.Dial("tcp", "localhost:5900")
		if err != nil {
			log.Printf("VNC TCP connect failed: %v", err)
			time.Sleep(1 * time.Second)
			continue
		}

		vncconn, err := NewVNCClient(vncnic)
		if err != nil {
			log.Printf("VNC handshake failed: %v", err)
			_ = vncnic.Close()
			time.Sleep(1 * time.Second)
			continue
		}

		log.Println("VNC connection ready")
		return vncconn
	}
}

func sendVNCKeyStroke(vncconn *VNCClient, stroke VNCKeyStroke) error {
	for _, modifier := range stroke.Modifiers {
		if err := vncconn.KeyEvent(modifier, true); err != nil {
			return err
		}
	}
	if err := vncconn.KeyEvent(stroke.Key, true); err != nil {
		return err
	}
	if err := vncconn.KeyEvent(stroke.Key, false); err != nil {
		return err
	}
	for i := len(stroke.Modifiers) - 1; i >= 0; i-- {
		if err := vncconn.KeyEvent(stroke.Modifiers[i], false); err != nil {
			return err
		}
	}
	return nil
}

func parseSSHKeyStream(input []byte, force bool) ([]VNCKeyStroke, []byte) {
	var strokes []VNCKeyStroke
	for i := 0; i < len(input); {
		if input[i] != 0x1b {
			stroke, ok := sshBytesToVNCKeyStroke(input[i])
			if !ok {
				log.Printf("Ignoring control byte: 0x%02x", input[i])
				i++
				continue
			}
			strokes = append(strokes, stroke)
			i++
			continue
		}

		stroke, consumed, complete, ok := parseEscapeSequence(input[i:], force)
		if !complete {
			return strokes, input[i:]
		}
		if ok {
			strokes = append(strokes, stroke)
			i += consumed
			continue
		}

		strokes = append(strokes, VNCKeyStroke{Key: vncKeyEscape})
		i++
	}
	return strokes, nil
}

func parseEscapeSequence(seq []byte, force bool) (VNCKeyStroke, int, bool, bool) {
	if len(seq) == 0 || seq[0] != 0x1b {
		return VNCKeyStroke{}, 0, true, false
	}
	if len(seq) == 1 {
		if force {
			return VNCKeyStroke{Key: vncKeyEscape}, 1, true, true
		}
		return VNCKeyStroke{}, 0, false, false
	}

	switch seq[1] {
	case '[':
		return parseCSISequence(seq, force)
	case 'O':
		return parseSS3Sequence(seq, force)
	default:
		stroke, ok := sshBytesToVNCKeyStroke(seq[1])
		if !ok {
			return VNCKeyStroke{Key: vncKeyEscape}, 1, true, true
		}
		stroke.Modifiers = append([]uint32{vncKeyAltL}, stroke.Modifiers...)
		return stroke, 2, true, true
	}
}

func parseCSISequence(seq []byte, force bool) (VNCKeyStroke, int, bool, bool) {
	finalIdx := -1
	for i := 2; i < len(seq); i++ {
		if seq[i] >= 0x40 && seq[i] <= 0x7e {
			finalIdx = i
			break
		}
	}
	if finalIdx == -1 {
		if force {
			return VNCKeyStroke{Key: vncKeyEscape}, 1, true, true
		}
		return VNCKeyStroke{}, 0, false, false
	}

	params := string(seq[2:finalIdx])
	final := seq[finalIdx]
	stroke, ok := csiToVNCKeyStroke(final, params)
	return stroke, finalIdx + 1, true, ok
}

func parseSS3Sequence(seq []byte, force bool) (VNCKeyStroke, int, bool, bool) {
	if len(seq) < 3 {
		if force {
			return VNCKeyStroke{Key: vncKeyEscape}, 1, true, true
		}
		return VNCKeyStroke{}, 0, false, false
	}

	stroke, ok := ss3ToVNCKeyStroke(seq[2])
	return stroke, 3, true, ok
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

func sshBytesToVNCKeyStroke(b byte) (VNCKeyStroke, bool) {
	if key, ok := controlByteToVNCKey(b); ok {
		return VNCKeyStroke{Key: key, Modifiers: []uint32{vncKeyControlL}}, true
	}

	switch b {
	case '\r', '\n':
		return VNCKeyStroke{Key: vncKeyReturn}, true
	case 0x7f, 0x08:
		return VNCKeyStroke{Key: vncKeyBackSpace}, true
	case '\t':
		return VNCKeyStroke{Key: vncKeyTab}, true
	case 0x1b:
		return VNCKeyStroke{Key: vncKeyEscape}, true
	}
	if b < 0x20 {
		return VNCKeyStroke{}, false
	}
	return VNCKeyStroke{Key: uint32(b)}, true
}

func csiToVNCKeyStroke(final byte, params string) (VNCKeyStroke, bool) {
	if final == 'Z' {
		return VNCKeyStroke{Key: vncKeyTab, Modifiers: []uint32{vncKeyShiftL}}, true
	}

	modifiers := csiModifiers(params)
	switch final {
	case 'A':
		return VNCKeyStroke{Key: vncKeyUp, Modifiers: modifiers}, true
	case 'B':
		return VNCKeyStroke{Key: vncKeyDown, Modifiers: modifiers}, true
	case 'C':
		return VNCKeyStroke{Key: vncKeyRight, Modifiers: modifiers}, true
	case 'D':
		return VNCKeyStroke{Key: vncKeyLeft, Modifiers: modifiers}, true
	case 'H':
		return VNCKeyStroke{Key: vncKeyHome, Modifiers: modifiers}, true
	case 'F':
		return VNCKeyStroke{Key: vncKeyEnd, Modifiers: modifiers}, true
	case '~':
		parts := splitCSIParams(params)
		if len(parts) == 0 {
			return VNCKeyStroke{}, false
		}
		key, ok := tildeCSIKey(parts[0])
		if !ok {
			return VNCKeyStroke{}, false
		}
		return VNCKeyStroke{Key: key, Modifiers: modifiers}, true
	}
	return VNCKeyStroke{}, false
}

func ss3ToVNCKeyStroke(final byte) (VNCKeyStroke, bool) {
	switch final {
	case 'A':
		return VNCKeyStroke{Key: vncKeyUp}, true
	case 'B':
		return VNCKeyStroke{Key: vncKeyDown}, true
	case 'C':
		return VNCKeyStroke{Key: vncKeyRight}, true
	case 'D':
		return VNCKeyStroke{Key: vncKeyLeft}, true
	case 'H':
		return VNCKeyStroke{Key: vncKeyHome}, true
	case 'F':
		return VNCKeyStroke{Key: vncKeyEnd}, true
	case 'P':
		return VNCKeyStroke{Key: 0xFFBE}, true
	case 'Q':
		return VNCKeyStroke{Key: 0xFFBF}, true
	case 'R':
		return VNCKeyStroke{Key: 0xFFC0}, true
	case 'S':
		return VNCKeyStroke{Key: 0xFFC1}, true
	}
	return VNCKeyStroke{}, false
}

func tildeCSIKey(code string) (uint32, bool) {
	switch code {
	case "1", "7":
		return vncKeyHome, true
	case "2":
		return vncKeyInsert, true
	case "3":
		return vncKeyDelete, true
	case "4", "8":
		return vncKeyEnd, true
	case "5":
		return vncKeyPageUp, true
	case "6":
		return vncKeyPageDown, true
	case "11":
		return 0xFFBE, true
	case "12":
		return 0xFFBF, true
	case "13":
		return 0xFFC0, true
	case "14":
		return 0xFFC1, true
	case "15":
		return 0xFFC2, true
	case "17":
		return 0xFFC3, true
	case "18":
		return 0xFFC4, true
	case "19":
		return 0xFFC5, true
	case "20":
		return 0xFFC6, true
	case "21":
		return 0xFFC7, true
	case "23":
		return 0xFFC8, true
	case "24":
		return 0xFFC9, true
	}
	return 0, false
}

func csiModifiers(params string) []uint32 {
	parts := splitCSIParams(params)
	if len(parts) < 2 {
		return nil
	}

	mod, err := strconv.Atoi(parts[len(parts)-1])
	if err != nil {
		return nil
	}
	return xtermModifierCodeToVNC(mod)
}

func splitCSIParams(params string) []string {
	if params == "" {
		return nil
	}
	raw := strings.Split(params, ";")
	out := make([]string, 0, len(raw))
	for _, part := range raw {
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

func xtermModifierCodeToVNC(mod int) []uint32 {
	var out []uint32
	switch mod {
	case 2:
		out = append(out, vncKeyShiftL)
	case 3:
		out = append(out, vncKeyAltL)
	case 4:
		out = append(out, vncKeyShiftL, vncKeyAltL)
	case 5:
		out = append(out, vncKeyControlL)
	case 6:
		out = append(out, vncKeyShiftL, vncKeyControlL)
	case 7:
		out = append(out, vncKeyAltL, vncKeyControlL)
	case 8:
		out = append(out, vncKeyShiftL, vncKeyAltL, vncKeyControlL)
	}
	return out
}
