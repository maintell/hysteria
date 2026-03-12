package obfs

import (
	"crypto/rand"
)

const (
	wrHeaderLen = 12 // fake RTP header length
	wrSaltLen   = 8
)

var _ Obfuscator = (*WebrtcObfuscator)(nil)

// WebrtcObfuscator wraps payloads into a RTP-like header + per-packet salt
// for traffic masquerading. It does NOT encrypt the payload — payload bytes
// are copied verbatim. Packet format: [12-byte rtp-like header][8-byte salt][payload]
type WebrtcObfuscator struct{}

// NewWebrtcObfuscator creates a new obfuscator. The constructor accepts an
// optional PSK parameter for compatibility but ignores it because this
// obfuscator does not perform encryption.
func NewWebrtcObfuscator(_ []byte) (*WebrtcObfuscator, error) {
	return &WebrtcObfuscator{}, nil
}

func (o *WebrtcObfuscator) Obfuscate(in, out []byte) int {
	outLen := wrHeaderLen + wrSaltLen + len(in)
	if len(out) < outLen {
		return 0
	}

	// Build a plausible RTP header
	// V=2, no padding/extensions, CC=0
	out[0] = 0x80
	// Dynamic payload type
	out[1] = 96

	// sequence number (2 bytes)
	var tmp2 [2]byte
	if _, err := rand.Read(tmp2[:]); err != nil {
		return 0
	}
	copy(out[2:4], tmp2[:])

	// timestamp (4 bytes)
	var tmp4a [4]byte
	if _, err := rand.Read(tmp4a[:]); err != nil {
		return 0
	}
	copy(out[4:8], tmp4a[:])

	// ssrc (4 bytes)
	var tmp4b [4]byte
	if _, err := rand.Read(tmp4b[:]); err != nil {
		return 0
	}
	copy(out[8:12], tmp4b[:])

	// salt (purely decorative for masquerade)
	if _, err := rand.Read(out[wrHeaderLen : wrHeaderLen+wrSaltLen]); err != nil {
		return 0
	}

	// Copy payload verbatim (no encryption)
	copy(out[wrHeaderLen+wrSaltLen:], in)
	return outLen
}

func (o *WebrtcObfuscator) Deobfuscate(in, out []byte) int {
	// minimal check: must contain header + salt + at least 1 byte payload
	if len(in) <= wrHeaderLen+wrSaltLen || len(out) < len(in)-wrHeaderLen-wrSaltLen {
		return 0
	}

	// Basic plausibility check: RTP version
	if (in[0] & 0xC0) != 0x80 {
		return 0
	}

	payload := in[wrHeaderLen+wrSaltLen:]
	copy(out, payload)
	return len(payload)
}
