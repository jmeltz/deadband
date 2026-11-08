package discover

import (
	"bytes"
	"net"
	"strconv"
	"strings"
	"time"
)

// Minimal zero-dependency, strictly read-only SNMPv2c sysDescr.0 (1.3.6.1.2.1.1.1.0)
// query helper used as an unauthenticated fallback for Siemens S7-1500/ET200SP PLCs
// (when classic S7comm PUT/GET is disabled) and MDF thermal/UPS management cards.

var snmpSysDescrOID = []byte{0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00}

func buildSNMPv2cGetSysDescr(community string) []byte {
	if community == "" {
		community = "public"
	}
	// OID TLV: 06 08 2b 06 01 02 01 01 01 00
	oidTLV := append([]byte{0x06, byte(len(snmpSysDescrOID))}, snmpSysDescrOID...)
	nullTLV := []byte{0x05, 0x00}
	varBind := wrapBERTLV(0x30, append(oidTLV, nullTLV...))
	varBindList := wrapBERTLV(0x30, varBind)

	reqID := []byte{0x02, 0x04, 0x44, 0x42, 0x00, 0x01} // INTEGER "DB\x00\x01"
	errStatus := []byte{0x02, 0x01, 0x00}
	errIndex := []byte{0x02, 0x01, 0x00}

	pduBody := make([]byte, 0, len(reqID)+len(errStatus)+len(errIndex)+len(varBindList))
	pduBody = append(pduBody, reqID...)
	pduBody = append(pduBody, errStatus...)
	pduBody = append(pduBody, errIndex...)
	pduBody = append(pduBody, varBindList...)
	getPDU := wrapBERTLV(0xA0, pduBody) // GetRequest-PDU

	verTLV := []byte{0x02, 0x01, 0x01} // version = 1 (SNMPv2c)
	commTLV := wrapBERTLV(0x04, []byte(community))

	msgBody := make([]byte, 0, len(verTLV)+len(commTLV)+len(getPDU))
	msgBody = append(msgBody, verTLV...)
	msgBody = append(msgBody, commTLV...)
	msgBody = append(msgBody, getPDU...)
	return wrapBERTLV(0x30, msgBody)
}

func wrapBERTLV(tag byte, val []byte) []byte {
	n := len(val)
	if n < 0x80 {
		out := make([]byte, 2+n)
		out[0] = tag
		out[1] = byte(n)
		copy(out[2:], val)
		return out
	}
	out := make([]byte, 4+n)
	out[0] = tag
	out[1] = 0x82
	out[2] = byte(n >> 8)
	out[3] = byte(n)
	copy(out[4:], val)
	return out
}

func readBERTLV(b []byte) (tag byte, val []byte, rest []byte, ok bool) {
	if len(b) < 2 {
		return 0, nil, nil, false
	}
	tag = b[0]
	l := int(b[1])
	hdr := 2
	if l&0x80 != 0 {
		numBytes := l & 0x7F
		if numBytes == 0 || numBytes > 2 || len(b) < 2+numBytes {
			return 0, nil, nil, false
		}
		l = 0
		for i := 0; i < numBytes; i++ {
			l = (l << 8) | int(b[2+i])
		}
		hdr = 2 + numBytes
	}
	if hdr+l > len(b) {
		return 0, nil, nil, false
	}
	return tag, b[hdr : hdr+l], b[hdr+l:], true
}

// ParseSNMPSysDescrResponse extracts the sysDescr.0 string from an SNMP GetResponse packet.
func ParseSNMPSysDescrResponse(pkt []byte) string {
	tag, msg, _, ok := readBERTLV(pkt)
	if !ok || tag != 0x30 {
		return ""
	}
	// Version
	tag, _, msg, ok = readBERTLV(msg)
	if !ok || tag != 0x02 {
		return ""
	}
	// Community
	tag, _, msg, ok = readBERTLV(msg)
	if !ok || tag != 0x04 {
		return ""
	}
	// GetResponse-PDU (0xA2)
	tag, pdu, _, ok := readBERTLV(msg)
	if !ok || tag != 0xA2 {
		return ""
	}
	// RequestID
	tag, _, pdu, ok = readBERTLV(pdu)
	if !ok || tag != 0x02 {
		return ""
	}
	// ErrorStatus (must be 0)
	tag, errStat, pdu, ok := readBERTLV(pdu)
	if !ok || tag != 0x02 || (len(errStat) > 0 && errStat[len(errStat)-1] != 0) {
		return ""
	}
	// ErrorIndex
	tag, _, pdu, ok = readBERTLV(pdu)
	if !ok || tag != 0x02 {
		return ""
	}
	// VarBindList
	tag, vbl, _, ok := readBERTLV(pdu)
	if !ok || tag != 0x30 {
		return ""
	}
	// First VarBind
	tag, vb, _, ok := readBERTLV(vbl)
	if !ok || tag != 0x30 {
		return ""
	}
	// OID
	tag, oid, vb, ok := readBERTLV(vb)
	if !ok || tag != 0x06 || !bytes.Equal(oid, snmpSysDescrOID) {
		return ""
	}
	// OCTET STRING value
	tag, strVal, _, ok := readBERTLV(vb)
	if !ok || tag != 0x04 {
		return ""
	}
	return strings.TrimSpace(string(strVal))
}

// SNMPGetSysDescr sends a single read-only SNMPv2c GetRequest for sysDescr.0 (community "public")
// to ip:port (default UDP/161) and returns the trimmed sysDescr string, or "" on timeout/error.
func SNMPGetSysDescr(ip string, port int, timeout time.Duration) string {
	if port <= 0 {
		port = SNMPPort
	}
	if timeout <= 0 {
		timeout = 750 * time.Millisecond
	}
	addr := net.JoinHostPort(ip, strconv.Itoa(port))
	conn, err := net.DialTimeout("udp", addr, timeout)
	if err != nil {
		return ""
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(timeout))
	if _, err := conn.Write(buildSNMPv2cGetSysDescr("public")); err != nil {
		return ""
	}

	buf := make([]byte, 1500)
	n, err := conn.Read(buf)
	if err != nil || n == 0 {
		return ""
	}
	return ParseSNMPSysDescrResponse(buf[:n])
}
