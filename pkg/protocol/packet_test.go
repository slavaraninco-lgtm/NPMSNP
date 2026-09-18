package protocol

import (
	"bufio"
	"bytes"
	"strings"
	"testing"
)

func TestPacketParsing(t *testing.T) {
	raw := "VER 1 MSNP9 MSNP8 CVR0\r\n"
	reader := bufio.NewReader(bytes.NewReader([]byte(raw)))
	pkt, err := ReadPacket(reader)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if pkt.Command != "VER" {
		t.Errorf("expected cmd VER, got %s", pkt.Command)
	}
	if len(pkt.Args) != 4 || pkt.Args[0] != "1" || pkt.Args[1] != "MSNP9" {
		t.Errorf("args mismatch: %v", pkt.Args)
	}

	formatted := FormatCommand("VER", false, "1", "MSNP9", "CVR0")
	if formatted != "VER 1 MSNP9 CVR0\r\n" {
		t.Errorf("format mismatch: got %q", formatted)
	}
}

func TestPayloadPacket(t *testing.T) {
	payload := "Hello World!"
	pktRaw := FormatPayloadCommand("MSG", []byte(payload), false, "user@msn.local", "User")
	reader := bufio.NewReader(bytes.NewReader(pktRaw))
	pkt, err := ReadPacket(reader)
	if err != nil {
		t.Fatalf("read error: %v", err)
	}
	if pkt.Command != "MSG" {
		t.Errorf("expected MSG, got %s", pkt.Command)
	}
	if string(pkt.Payload) != payload {
		t.Errorf("payload mismatch: expected %q, got %q", payload, string(pkt.Payload))
	}
}

func TestEncoding(t *testing.T) {
	original := "Привет, мир!"
	cpBytes := UTF8ToCP1251(original)
	decoded := CP1251ToUTF8(cpBytes)
	if decoded != original {
		t.Errorf("CP1251 roundtrip failed: got %q, expected %q", decoded, original)
	}

	argUTF8 := EncodeArg("Служба сообщений MSN", false)
	if strings.Contains(argUTF8, " ") {
		t.Errorf("encoded arg should not contain raw spaces: %s", argUTF8)
	}

	argANSI := EncodeArg("Служба сообщений MSN", true)
	if strings.Contains(argANSI, " ") {
		t.Errorf("encoded ANSI arg should not contain raw spaces: %s", argANSI)
	}
	decodedANSI := DecodeArg(argANSI)
	if decodedANSI != "Служба сообщений MSN" {
		t.Errorf("decoded ANSI mismatch: got %q", decodedANSI)
	}
}
