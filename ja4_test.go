package main

import (
	"crypto/md5"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"sort"
	"strings"
	"testing"
	"time"
)

// Loopback regression: the real newTransport() ClientHello must hash to the
// official Antigravity language_server target. Reads the first ClientHello and
// closes; no handshake, no network. Fails if a Go upgrade moves the Hello.
const (
	targetJA4     = "t13d1312h2_f57a46bbacb6_f50d94e863eb"
	targetJA3Hash = "03117a8ed39ef02427ebbc39f121275c"
)

func isGrease(v uint16) bool { return v&0x0f0f == 0x0a0a && v>>8 == v&0xff }

func u16s(b []byte) []uint16 {
	out := make([]uint16, 0, len(b)/2)
	for i := 0; i+1 < len(b); i += 2 {
		out = append(out, binary.BigEndian.Uint16(b[i:]))
	}
	return out
}

func noGrease(xs []uint16) []uint16 {
	var out []uint16
	for _, x := range xs {
		if !isGrease(x) {
			out = append(out, x)
		}
	}
	return out
}

func joinU16(xs []uint16, sep, f string) string {
	s := make([]string, len(xs))
	for i, x := range xs {
		s[i] = fmt.Sprintf(f, x)
	}
	return strings.Join(s, sep)
}

// fingerprint takes the handshake message (record headers stripped).
func fingerprint(hs []byte) (ja3, ja4, ja4r string) {
	b := hs[4:]
	ver := binary.BigEndian.Uint16(b)
	q := 34
	q += 1 + int(b[q])
	n := int(binary.BigEndian.Uint16(b[q:]))
	ciphers := u16s(b[q+2 : q+2+n])
	q += 2 + n
	q += 1 + int(b[q])
	end := q + 2 + int(binary.BigEndian.Uint16(b[q:]))
	q += 2
	var exts, groups, sig, sv []uint16
	var pf []byte
	sni, alpn := false, ""
	for q+4 <= end {
		t := binary.BigEndian.Uint16(b[q:])
		l := int(binary.BigEndian.Uint16(b[q+2:]))
		d := b[q+4 : q+4+l]
		q += 4 + l
		exts = append(exts, t)
		switch t {
		case 0:
			sni = true
		case 10:
			groups = u16s(d[2 : 2+int(binary.BigEndian.Uint16(d))])
		case 11:
			pf = d[1 : 1+int(d[0])]
		case 13:
			sig = u16s(d[2 : 2+int(binary.BigEndian.Uint16(d))])
		case 16:
			if alpn == "" && len(d) > 3 {
				alpn = string(d[3 : 3+int(d[2])])
			}
		case 43:
			sv = u16s(d[1 : 1+int(d[0])])
		}
	}
	c, e, g := noGrease(ciphers), noGrease(exts), noGrease(groups)
	pfs := make([]string, len(pf))
	for i, x := range pf {
		pfs[i] = fmt.Sprint(x)
	}
	ja3 = fmt.Sprintf("%d,%s,%s,%s,%s", ver, joinU16(c, "-", "%d"), joinU16(e, "-", "%d"), joinU16(g, "-", "%d"), strings.Join(pfs, "-"))

	top := ver
	for _, x := range noGrease(sv) {
		if x > top {
			top = x
		}
	}
	v := map[uint16]string{0x0304: "13", 0x0303: "12", 0x0302: "11", 0x0301: "10"}[top]
	if v == "" {
		v = "00"
	}
	a := "00"
	if alpn != "" {
		a = alpn[:1] + alpn[len(alpn)-1:]
	}
	d := "i"
	if sni {
		d = "d"
	}
	pre := fmt.Sprintf("t%s%s%02d%02d%s", v, d, len(c), len(e), a)
	cs := append([]uint16(nil), c...)
	sort.Slice(cs, func(i, j int) bool { return cs[i] < cs[j] })
	var es []uint16
	for _, x := range e {
		if x != 0 && x != 16 {
			es = append(es, x)
		}
	}
	sort.Slice(es, func(i, j int) bool { return es[i] < es[j] })
	css, ess, sss := joinU16(cs, ",", "%04x"), joinU16(es, ",", "%04x"), joinU16(noGrease(sig), ",", "%04x")
	h12 := func(s string) string { x := sha256.Sum256([]byte(s)); return hex.EncodeToString(x[:])[:12] }
	partC := ess
	if sss != "" {
		partC += "_" + sss
	}
	ja4 = fmt.Sprintf("%s_%s_%s", pre, h12(css), h12(partC))
	return ja3, ja4, fmt.Sprintf("%s_%s_%s_%s", pre, css, ess, sss)
}

// readClientHello reads until the first handshake message is complete.
func readClientHello(c net.Conn) ([]byte, error) {
	var raw []byte
	buf := make([]byte, 16384)
	for {
		n, err := c.Read(buf)
		raw = append(raw, buf[:n]...)
		var hs []byte
		for p := 0; p+5 <= len(raw) && raw[p] == 0x16; {
			l := int(binary.BigEndian.Uint16(raw[p+3:]))
			if p+5+l > len(raw) {
				break
			}
			hs = append(hs, raw[p+5:p+5+l]...)
			p += 5 + l
		}
		if len(hs) >= 4 && len(hs) >= 4+(int(hs[1])<<16|int(hs[2])<<8|int(hs[3])) {
			return hs, nil
		}
		if err != nil {
			return nil, err
		}
	}
}

func TestClientHelloMatchesTarget(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	got := make(chan []byte, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			got <- nil
			return
		}
		c.SetDeadline(time.Now().Add(10 * time.Second))
		hs, _ := readClientHello(c)
		c.Close() // client handshake fails afterwards, as expected
		got <- hs
	}()
	cl := &http.Client{Transport: newTransport(), Timeout: 10 * time.Second}
	// hostname, not IP: SNI must be present for the JA4 "d" prefix
	if resp, err := cl.Get(fmt.Sprintf("https://localhost:%d/", ln.Addr().(*net.TCPAddr).Port)); err == nil {
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}
	hs := <-got
	if hs == nil || hs[0] != 1 {
		t.Fatal("no ClientHello captured")
	}
	ja3, ja4, ja4r := fingerprint(hs)
	if ja4 != targetJA4 {
		t.Errorf("JA4 drift: got %s want %s; ja4_r=%s", ja4, targetJA4, ja4r)
	}
	if h := md5.Sum([]byte(ja3)); hex.EncodeToString(h[:]) != targetJA3Hash {
		t.Errorf("JA3 drift: got %x want %s; ja3=%s", h, targetJA3Hash, ja3)
	}
}
