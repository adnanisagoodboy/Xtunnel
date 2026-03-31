// Package ws implements a minimal WebSocket server using only stdlib.
// Supports text and binary frames, ping/pong, close handshake.
package ws

import (
	"bufio"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
)

const wsGUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

// Conn is a WebSocket connection
type Conn struct {
	conn   net.Conn
	rw     *bufio.ReadWriter
	server bool
}

// Upgrade upgrades an HTTP connection to WebSocket
func Upgrade(w http.ResponseWriter, r *http.Request) (*Conn, error) {
	if !strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
		return nil, fmt.Errorf("not a websocket upgrade request")
	}
	key := r.Header.Get("Sec-Websocket-Key")
	if key == "" {
		return nil, fmt.Errorf("missing Sec-WebSocket-Key")
	}

	accept := computeAccept(key)

	hj, ok := w.(http.Hijacker)
	if !ok {
		return nil, fmt.Errorf("hijacking not supported")
	}
	conn, rw, err := hj.Hijack()
	if err != nil {
		return nil, err
	}

	// Send 101 Switching Protocols
	resp := "HTTP/1.1 101 Switching Protocols\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Accept: " + accept + "\r\n\r\n"
	rw.WriteString(resp)
	rw.Flush()

	return &Conn{conn: conn, rw: rw, server: true}, nil
}

// Message types
const (
	OpText   = 0x1
	OpBinary = 0x2
	OpClose  = 0x8
	OpPing   = 0x9
	OpPong   = 0xA
)

type Message struct {
	Op   int
	Data []byte
}

// ReadMessage reads one complete WebSocket message (handles fragmentation)
func (c *Conn) ReadMessage() (*Message, error) {
	var fullData []byte
	var finalOp int

	for {
		fin, op, data, err := c.readFrame()
		if err != nil {
			return nil, err
		}

		// Control frames (close/ping/pong) are never fragmented
		switch op {
		case OpClose:
			c.WriteMessage(OpClose, []byte{})
			return &Message{Op: OpClose}, nil
		case OpPing:
			c.WriteMessage(OpPong, data)
			continue
		case OpPong:
			continue
		}

		if len(fullData) == 0 {
			finalOp = op
		}
		fullData = append(fullData, data...)

		if fin {
			return &Message{Op: finalOp, Data: fullData}, nil
		}
	}
}

func (c *Conn) readFrame() (fin bool, op int, data []byte, err error) {
	// Read first 2 bytes
	header := make([]byte, 2)
	if _, err = io.ReadFull(c.rw, header); err != nil {
		return
	}

	fin = header[0]&0x80 != 0
	op = int(header[0] & 0x0F)
	masked := header[1]&0x80 != 0
	payloadLen := int64(header[1] & 0x7F)

	// Extended payload length
	switch payloadLen {
	case 126:
		var ext [2]byte
		if _, err = io.ReadFull(c.rw, ext[:]); err != nil {
			return
		}
		payloadLen = int64(binary.BigEndian.Uint16(ext[:]))
	case 127:
		var ext [8]byte
		if _, err = io.ReadFull(c.rw, ext[:]); err != nil {
			return
		}
		payloadLen = int64(binary.BigEndian.Uint64(ext[:]))
	}

	// Masking key (client → server frames are always masked per spec)
	var maskKey [4]byte
	if masked {
		if _, err = io.ReadFull(c.rw, maskKey[:]); err != nil {
			return
		}
	}

	// Payload
	data = make([]byte, payloadLen)
	if _, err = io.ReadFull(c.rw, data); err != nil {
		return
	}

	// Unmask
	if masked {
		for i := range data {
			data[i] ^= maskKey[i%4]
		}
	}
	return
}

// WriteMessage sends a WebSocket frame
func (c *Conn) WriteMessage(op int, data []byte) error {
	frame := buildFrame(op, data, false) // server never masks
	_, err := c.rw.Write(frame)
	if err != nil {
		return err
	}
	return c.rw.Flush()
}

func buildFrame(op int, data []byte, masked bool) []byte {
	length := len(data)
	var buf []byte

	// First byte: FIN + opcode
	buf = append(buf, byte(0x80|op))

	// Second byte: mask bit + payload length
	maskBit := byte(0)
	if masked {
		maskBit = 0x80
	}
	switch {
	case length <= 125:
		buf = append(buf, maskBit|byte(length))
	case length <= 65535:
		buf = append(buf, maskBit|126)
		buf = append(buf, byte(length>>8), byte(length))
	default:
		buf = append(buf, maskBit|127)
		var ext [8]byte
		binary.BigEndian.PutUint64(ext[:], uint64(length))
		buf = append(buf, ext[:]...)
	}

	buf = append(buf, data...)
	return buf
}

func (c *Conn) Close() error {
	c.WriteMessage(OpClose, []byte{})
	return c.conn.Close()
}

func (c *Conn) RemoteAddr() net.Addr {
	return c.conn.RemoteAddr()
}

func computeAccept(key string) string {
	h := sha1.New()
	h.Write([]byte(key + wsGUID))
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}
