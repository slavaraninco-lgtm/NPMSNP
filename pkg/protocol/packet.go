package protocol

import (
	"bufio"
	"bytes"
	"io"
	"strconv"
	"strings"
)

// Packet represents an incoming or outgoing MSNP command packet.
type Packet struct {
	Command string
	Args    []string
	Payload []byte
}

// Commands that always carry a payload when payload_len is given
var payloadCommands = map[string]bool{
	"MSG": true,
	"NOT": true,
	"UUX": true,
	"UBX": true,
	"IPG": true,
	"GCF": true,
	"ADL": true,
	"RML": true,
	"SDG": true,
	"SDC": true,
	"PUT": true,
	"QRY": true,
	"UUN": true,
	"UUM": true,
	"VAS": true,
}

// ReadPacket reads one MSNP packet from a buffered reader.
func ReadPacket(r *bufio.Reader) (*Packet, error) {
	line, err := r.ReadBytes('\n')
	if err != nil {
		return nil, err
	}

	line = bytes.TrimRight(line, "\r\n")
	if len(line) == 0 {
		return &Packet{}, nil
	}

	rawParts := bytes.Split(line, []byte(" "))
	cmd := strings.ToUpper(string(rawParts[0]))
	rawArgs := rawParts[1:]

	var payload []byte
	var args []string

	if payloadCommands[cmd] && len(rawArgs) > 0 {
		lastArgStr := string(rawArgs[len(rawArgs)-1])
		if length, err := strconv.Atoi(lastArgStr); err == nil && length >= 0 {
			payload = make([]byte, length)
			if _, err := io.ReadFull(r, payload); err != nil {
				return nil, err
			}
			for _, a := range rawArgs[:len(rawArgs)-1] {
				args = append(args, DecodeArgBytes(a))
			}
			args = append(args, lastArgStr)
		} else {
			for _, a := range rawArgs {
				args = append(args, DecodeArgBytes(a))
			}
		}
	} else {
		for _, a := range rawArgs {
			args = append(args, DecodeArgBytes(a))
		}
	}

	return &Packet{
		Command: cmd,
		Args:    args,
		Payload: payload,
	}, nil
}

// FormatCommand formats an MSNP command string: CMD ARG1 ARG2...\r\n
// Non-ASCII and spaces are percent-encoded with EncodeArg so argument boundaries are never corrupted.
func FormatCommand(cmd string, isANSI bool, args ...interface{}) string {
	parts := make([]string, 0, 1+len(args))
	parts = append(parts, cmd)
	for _, a := range args {
		parts = append(parts, EncodeArg(a, isANSI))
	}
	return strings.Join(parts, " ") + "\r\n"
}

// FormatPayloadCommand formats an MSNP command with a binary payload:
// CMD ARG1 ARG2... LEN\r\n<PAYLOAD>
func FormatPayloadCommand(cmd string, payload []byte, isANSI bool, args ...interface{}) []byte {
	var buf bytes.Buffer
	buf.WriteString(cmd)
	for _, a := range args {
		buf.WriteByte(' ')
		buf.WriteString(EncodeArg(a, isANSI))
	}
	buf.WriteByte(' ')
	buf.WriteString(strconv.Itoa(len(payload)))
	buf.WriteString("\r\n")
	buf.Write(payload)
	return buf.Bytes()
}
