package protocol

import (
	"bytes"
	"fmt"
	"strconv"
	"strings"
)

// Unicode <-> Windows-1251 mapping table for Russian/Cyrillic characters.
var unicodeToCP1251 = map[rune]byte{
	0x0402: 0x80, // Ђ
	0x0403: 0x81, // Ѓ
	0x201A: 0x82, // ‚
	0x0453: 0x83, // ѓ
	0x201E: 0x84, // „
	0x2026: 0x85, // …
	0x2020: 0x86, // †
	0x2021: 0x87, // ‡
	0x20AC: 0x88, // €
	0x2030: 0x89, // ‰
	0x0409: 0x8A, // Љ
	0x2039: 0x8B, // ‹
	0x040A: 0x8C, // Њ
	0x040C: 0x8D, // Ќ
	0x040B: 0x8E, // Ћ
	0x040F: 0x8F, // Џ
	0x0452: 0x90, // ђ
	0x2018: 0x91, // ‘
	0x2019: 0x92, // ’
	0x201C: 0x93, // “
	0x201D: 0x94, // ”
	0x2022: 0x95, // •
	0x2013: 0x96, // –
	0x2014: 0x97, // —
	0x2122: 0x99, // ™
	0x0459: 0x9A, // љ
	0x203A: 0x9B, // ›
	0x045A: 0x9C, // њ
	0x045C: 0x9D, // ќ
	0x045B: 0x9E, // ћ
	0x045F: 0x9F, // џ
	0x00A0: 0xA0, // NBSP
	0x040E: 0xA1, // Ў
	0x045E: 0xA2, // ў
	0x0408: 0xA3, // Ј
	0x00A4: 0xA4, // ¤
	0x0490: 0xA5, // Ґ
	0x00A6: 0xA6, // ¦
	0x00A7: 0xA7, // §
	0x0401: 0xA8, // Ё
	0x00A9: 0xA9, // ©
	0x0404: 0xAA, // Є
	0x00AB: 0xAB, // «
	0x00AC: 0xAC, // ¬
	0x00AD: 0xAD, // SOFT HYPHEN
	0x00AE: 0xAE, // ®
	0x0407: 0xAF, // Ї
	0x00B0: 0xB0, // °
	0x00B1: 0xB1, // ±
	0x0406: 0xB2, // І
	0x0456: 0xB3, // і
	0x0491: 0xB4, // ґ
	0x00B5: 0xB5, // µ
	0x00B6: 0xB6, // ¶
	0x00B7: 0xB7, // ·
	0x0451: 0xB8, // ё
	0x2116: 0xB9, // №
	0x0454: 0xBA, // є
	0x00BB: 0xBB, // »
	0x0458: 0xBC, // ј
	0x0405: 0xBD, // Ѕ
	0x0455: 0xBE, // ѕ
	0x0457: 0xBF, // ї
}

// UTF8ToCP1251 converts a UTF-8 string to Windows-1251 byte slice.
func UTF8ToCP1251(s string) []byte {
	out := make([]byte, 0, len(s))
	for _, r := range s {
		if r < 0x80 {
			out = append(out, byte(r))
		} else if r >= 0x0410 && r <= 0x044F {
			// Basic Russian Cyrillic: 0x0410 ('А') -> 0xC0 .. 0x044F ('я') -> 0xFF
			out = append(out, byte(r-0x0410+0xC0))
		} else if b, ok := unicodeToCP1251[r]; ok {
			out = append(out, b)
		} else {
			out = append(out, '?')
		}
	}
	return out
}

// CP1251ToUTF8 converts a Windows-1251 byte slice to UTF-8 string.
func CP1251ToUTF8(b []byte) string {
	var sb strings.Builder
	for _, c := range b {
		if c < 0x80 {
			sb.WriteByte(c)
		} else if c >= 0xC0 && c <= 0xFF {
			sb.WriteRune(rune(0x0410 + int(c) - 0xC0))
		} else {
			// Lookup reverse map
			found := false
			for r, cp := range unicodeToCP1251 {
				if cp == c {
					sb.WriteRune(r)
					found = true
					break
				}
			}
			if !found {
				sb.WriteByte('?')
			}
		}
	}
	return sb.String()
}

// isSafeChar returns true for characters that must NOT be percent-encoded in MSNP command arguments.
func isSafeChar(c byte) bool {
	// RFC 1738 safe set for MSNP: letters, digits, and @ / : - _ . ~ , = { } + * & ! $ ( ) #
	if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') {
		return true
	}
	switch c {
	case '@', '/', ':', '-', '_', '.', '~', ',', '=', '{', '}', '+', '*', '&', '!', '$', '(', ')', '#':
		return true
	}
	return false
}

// EncodeArg percent-encodes an MSNP command line argument.
// Crucially, SPACES ARE ENCODED as %20 so arguments never contain unencoded spaces.
// For ANSI clients (Trillian, Miranda, IM2), non-ASCII Cyrillic text is converted to CP1251 bytes first.
func EncodeArg(arg interface{}, isANSI bool) string {
	if arg == nil {
		return ""
	}
	s := fmt.Sprint(arg)
	if s == "" {
		return ""
	}

	var rawBytes []byte
	if isANSI {
		rawBytes = UTF8ToCP1251(s)
	} else {
		rawBytes = []byte(s)
	}

	var buf strings.Builder
	for _, b := range rawBytes {
		if isSafeChar(b) {
			buf.WriteByte(b)
		} else {
			buf.WriteString(fmt.Sprintf("%%%02X", b))
		}
	}
	return buf.String()
}

// DecodeArg unquotes percent-encoded %XX sequences in MSNP command line arguments.
func DecodeArg(s string) string {
	if !strings.Contains(s, "%") {
		return s
	}

	// Unquote at byte level
	raw := []byte(s)
	var unquoted []byte
	for i := 0; i < len(raw); {
		if raw[i] == '%' && i+2 < len(raw) {
			if b, err := strconv.ParseUint(string(raw[i+1:i+3]), 16, 8); err == nil {
				unquoted = append(unquoted, byte(b))
				i += 3
				continue
			}
		}
		unquoted = append(unquoted, raw[i])
		i++
	}

	// Try UTF-8 first
	str := string(unquoted)
	if strings.ToValidUTF8(str, "") == str {
		return str
	}

	// Fallback to CP1251
	return CP1251ToUTF8(unquoted)
}

// DecodeArgBytes decodes raw bytes from socket line.
func DecodeArgBytes(raw []byte) string {
	if len(raw) == 0 {
		return ""
	}
	// Check for %XX
	if bytes.Contains(raw, []byte("%")) {
		var unquoted []byte
		for i := 0; i < len(raw); {
			if raw[i] == '%' && i+2 < len(raw) {
				if b, err := strconv.ParseUint(string(raw[i+1:i+3]), 16, 8); err == nil {
					unquoted = append(unquoted, byte(b))
					i += 3
					continue
				}
			}
			unquoted = append(unquoted, raw[i])
			i++
		}
		// Try UTF-8
		str := string(unquoted)
		if strings.ToValidUTF8(str, "") == str {
			return str
		}
		return CP1251ToUTF8(unquoted)
	}

	// Plain raw bytes
	str := string(raw)
	if strings.ToValidUTF8(str, "") == str {
		return str
	}
	return CP1251ToUTF8(raw)
}
