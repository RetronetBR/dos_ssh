package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
)

// VNCClient implements the tiny portion of RFB we need: connect, authenticate
// with "none", finish the server init handshake, and send key events.
type VNCClient struct {
	conn   net.Conn
	mu     sync.Mutex
	width  uint16
	height uint16
}

func NewVNCClient(conn net.Conn) (*VNCClient, error) {
	client := &VNCClient{conn: conn}
	if err := client.handshake(); err != nil {
		_ = conn.Close()
		return nil, err
	}
	return client, nil
}

func (c *VNCClient) KeyEvent(key uint32, down bool) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	var msg [8]byte
	msg[0] = 4 // KeyEvent
	if down {
		msg[1] = 1
	}
	binary.BigEndian.PutUint32(msg[4:], key)

	_, err := c.conn.Write(msg[:])
	return err
}

func (c *VNCClient) handshake() error {
	version := make([]byte, 12)
	if _, err := io.ReadFull(c.conn, version); err != nil {
		return fmt.Errorf("read VNC version: %w", err)
	}

	serverVersion := string(version)
	switch {
	case strings.HasPrefix(serverVersion, "RFB 003.003"):
		if _, err := c.conn.Write([]byte("RFB 003.003\n")); err != nil {
			return fmt.Errorf("write VNC version: %w", err)
		}
		return c.handshake33()
	case strings.HasPrefix(serverVersion, "RFB 003.007"), strings.HasPrefix(serverVersion, "RFB 003.008"):
		if _, err := c.conn.Write([]byte("RFB 003.008\n")); err != nil {
			return fmt.Errorf("write VNC version: %w", err)
		}
		return c.handshake37()
	default:
		return fmt.Errorf("unsupported VNC server version %q", strings.TrimSpace(serverVersion))
	}
}

func (c *VNCClient) handshake33() error {
	var secType [4]byte
	if _, err := io.ReadFull(c.conn, secType[:]); err != nil {
		return fmt.Errorf("read security type: %w", err)
	}
	if binary.BigEndian.Uint32(secType[:]) != 1 {
		return fmt.Errorf("VNC server rejected no-auth security type")
	}
	return c.finishServerInit()
}

func (c *VNCClient) handshake37() error {
	var count [1]byte
	if _, err := io.ReadFull(c.conn, count[:]); err != nil {
		return fmt.Errorf("read security type count: %w", err)
	}
	if count[0] == 0 {
		reason, readErr := readVNCLengthPrefixedString(c.conn)
		if readErr != nil {
			return fmt.Errorf("read VNC auth failure reason: %w", readErr)
		}
		return fmt.Errorf("VNC server offered no security types: %s", reason)
	}

	types := make([]byte, count[0])
	if _, err := io.ReadFull(c.conn, types); err != nil {
		return fmt.Errorf("read security types: %w", err)
	}

	chosen := byte(0)
	for _, t := range types {
		if t == 1 {
			chosen = 1
			break
		}
	}
	if chosen == 0 {
		return fmt.Errorf("VNC server does not offer no-auth security")
	}
	if _, err := c.conn.Write([]byte{chosen}); err != nil {
		return fmt.Errorf("select security type: %w", err)
	}

	var result [4]byte
	if _, err := io.ReadFull(c.conn, result[:]); err != nil {
		return fmt.Errorf("read security result: %w", err)
	}
	if binary.BigEndian.Uint32(result[:]) != 0 {
		reason, readErr := readVNCLengthPrefixedString(c.conn)
		if readErr != nil {
			return fmt.Errorf("read VNC auth failure reason: %w", readErr)
		}
		return fmt.Errorf("VNC authentication failed: %s", reason)
	}

	return c.finishServerInit()
}

func (c *VNCClient) finishServerInit() error {
	if _, err := c.conn.Write([]byte{1}); err != nil { // shared-flag
		return fmt.Errorf("write client init: %w", err)
	}

	var header [24]byte
	if _, err := io.ReadFull(c.conn, header[:]); err != nil {
		return fmt.Errorf("read server init: %w", err)
	}

	c.width = binary.BigEndian.Uint16(header[0:2])
	c.height = binary.BigEndian.Uint16(header[2:4])

	nameLen := binary.BigEndian.Uint32(header[20:24])
	if nameLen > 0 {
		if _, err := io.CopyN(io.Discard, c.conn, int64(nameLen)); err != nil {
			return fmt.Errorf("read server name: %w", err)
		}
	}

	// Match go-vnc's default client behavior: finish the handshake and keep a
	// reader active, but do not request framebuffer data on this keyboard-only
	// connection. The DOS screen is captured separately through GDB.
	go c.drainServerMessages()

	return nil
}

func (c *VNCClient) drainServerMessages() {
	for {
		var msgType [1]byte
		if _, err := io.ReadFull(c.conn, msgType[:]); err != nil {
			return
		}

		switch msgType[0] {
		case 0:
			if err := c.discardFramebufferUpdate(); err != nil {
				return
			}
		case 2:
			continue
		case 3:
			if err := c.discardServerCutText(); err != nil {
				return
			}
		default:
			return
		}
	}
}

func (c *VNCClient) discardFramebufferUpdate() error {
	var hdr [3]byte
	if _, err := io.ReadFull(c.conn, hdr[:]); err != nil {
		return err
	}
	// The message type was already consumed by drainServerMessages. The next
	// bytes are one byte of padding followed by the rectangle count.
	nrects := binary.BigEndian.Uint16(hdr[1:3])
	for i := 0; i < int(nrects); i++ {
		var rectHdr [12]byte
		if _, err := io.ReadFull(c.conn, rectHdr[:]); err != nil {
			return err
		}
		w := binary.BigEndian.Uint16(rectHdr[4:6])
		h := binary.BigEndian.Uint16(rectHdr[6:8])
		encoding := binary.BigEndian.Uint32(rectHdr[8:12])
		if encoding != 0 {
			continue
		}
		_, err := io.CopyN(io.Discard, c.conn, int64(w)*int64(h)*4)
		if err != nil {
			return err
		}
	}
	return nil
}

func (c *VNCClient) discardServerCutText() error {
	var hdr [7]byte
	if _, err := io.ReadFull(c.conn, hdr[:]); err != nil {
		return err
	}
	length := binary.BigEndian.Uint32(hdr[3:7])
	if length > 0 {
		_, err := io.CopyN(io.Discard, c.conn, int64(length))
		if err != nil {
			return err
		}
	}
	return nil
}

func readVNCLengthPrefixedString(r io.Reader) (string, error) {
	var lenBuf [4]byte
	if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
		return "", err
	}

	n := binary.BigEndian.Uint32(lenBuf[:])
	if n == 0 {
		return "", nil
	}

	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return "", err
	}
	return string(bytes.TrimRight(buf, "\x00")), nil
}
