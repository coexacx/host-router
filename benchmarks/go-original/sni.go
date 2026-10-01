package main

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"strings"
)

var errNoName = errors.New("no SNI/Host found in first packet")

const (
	maxSniffBytes     = 128 * 1024
	maxTLSRecordBytes = 32 * 1024
)

func sniffHost(c net.Conn) (host string, prefix []byte, err error) {
	buf := make([]byte, 0, 4096)
	tmp := make([]byte, 4096)
	readMore := func() error {
		n, e := c.Read(tmp)
		if n > 0 {
			buf = append(buf, tmp[:n]...)
		}
		if len(buf) > maxSniffBytes {
			return fmt.Errorf("first packet exceeds %d bytes", maxSniffBytes)
		}
		return e
	}

	for len(buf) < 1 {
		if e := readMore(); e != nil {
			return "", buf, e
		}
	}

	if buf[0] == 0x16 {
		sni, e := tlsSNIFromRecords(&buf, readMore)
		if e != nil {
			return "", buf, e
		}
		if sni == "" {
			return "", buf, errNoName
		}
		return sni, buf, nil
	}

	for !bytes.Contains(buf, []byte("\r\n\r\n")) {
		if len(buf) > 64*1024 {
			break
		}
		if e := readMore(); e != nil {
			return "", buf, e
		}
	}
	if h := httpHost(buf); h != "" {
		return h, buf, nil
	}
	return "", buf, errNoName
}

func tlsSNIFromRecords(buf *[]byte, readMore func() error) (string, error) {
	var hello []byte
	off := 0
	for {
		for len(*buf) < off+5 {
			if err := readMore(); err != nil {
				return "", err
			}
		}
		b := *buf
		recordType := b[off]
		recordLen := int(b[off+3])<<8 | int(b[off+4])
		if recordLen <= 0 || recordLen > maxTLSRecordBytes {
			return "", fmt.Errorf("invalid TLS record length %d", recordLen)
		}
		need := off + 5 + recordLen
		if need > maxSniffBytes {
			return "", fmt.Errorf("TLS ClientHello exceeds %d bytes", maxSniffBytes)
		}
		for len(*buf) < need {
			if err := readMore(); err != nil {
				return "", err
			}
		}
		record := (*buf)[off+5 : need]
		off = need

		if recordType != 0x16 {
			if len(hello) == 0 {
				return "", errNoName
			}
			return "", fmt.Errorf("TLS ClientHello spans non-handshake record")
		}
		hello = append(hello, record...)
		if len(hello) > maxSniffBytes {
			return "", fmt.Errorf("TLS ClientHello exceeds %d bytes", maxSniffBytes)
		}
		if len(hello) < 4 {
			continue
		}
		if hello[0] != 0x01 {
			return "", errNoName
		}
		helloLen := int(hello[1])<<16 | int(hello[2])<<8 | int(hello[3])
		if helloLen <= 0 || helloLen > maxSniffBytes {
			return "", fmt.Errorf("invalid TLS ClientHello length %d", helloLen)
		}
		if len(hello) >= 4+helloLen {
			return extractSNIFromClientHello(hello[:4+helloLen]), nil
		}
	}
}

func httpHost(b []byte) string {
	end := bytes.Index(b, []byte("\r\n\r\n"))
	if end >= 0 {
		b = b[:end]
	}
	for _, line := range bytes.Split(b, []byte("\r\n")) {
		i := bytes.IndexByte(line, ':')
		if i < 0 {
			continue
		}
		if strings.EqualFold(strings.TrimSpace(string(line[:i])), "host") {
			h := strings.TrimSpace(string(line[i+1:]))
			if hh, _, e := net.SplitHostPort(h); e == nil {
				h = hh
			}
			return strings.ToLower(h)
		}
	}
	return ""
}

func extractSNIFromClientHello(b []byte) string {
	if len(b) < 4 || b[0] != 0x01 {
		return ""
	}
	helloLen := int(b[1])<<16 | int(b[2])<<8 | int(b[3])
	if len(b) < 4+helloLen {
		return ""
	}
	b = b[4:]
	if len(b) < 2+32 {
		return ""
	}
	b = b[2+32:]
	if len(b) < 1 || len(b) < 1+int(b[0]) {
		return ""
	}
	b = b[1+int(b[0]):]
	if len(b) < 2 {
		return ""
	}
	n := int(b[0])<<8 | int(b[1])
	if len(b) < 2+n {
		return ""
	}
	b = b[2+n:]
	if len(b) < 1 || len(b) < 1+int(b[0]) {
		return ""
	}
	b = b[1+int(b[0]):]
	if len(b) < 2 {
		return ""
	}
	extTotal := int(b[0])<<8 | int(b[1])
	b = b[2:]
	if len(b) > extTotal {
		b = b[:extTotal]
	}
	for len(b) >= 4 {
		extType := int(b[0])<<8 | int(b[1])
		l := int(b[2])<<8 | int(b[3])
		b = b[4:]
		if len(b) < l {
			return ""
		}
		ext := b[:l]
		b = b[l:]
		if extType != 0x00 {
			continue
		}
		if len(ext) < 2 {
			return ""
		}
		ext = ext[2:]
		for len(ext) >= 3 {
			nameType := ext[0]
			nl := int(ext[1])<<8 | int(ext[2])
			ext = ext[3:]
			if len(ext) < nl {
				return ""
			}
			if nameType == 0x00 {
				return string(ext[:nl])
			}
			ext = ext[nl:]
		}
	}
	return ""
}
