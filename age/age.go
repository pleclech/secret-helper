package age

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"strings"

	"filippo.io/age"
	"filippo.io/age/armor"
)

// Return true if the input maybe encrypted with age
func MaybeEncrypted(input string) bool {
	scanner := bufio.NewScanner(strings.NewReader(input))

	if !scanner.Scan() {
		return false
	}

	return strings.HasPrefix(strings.TrimSpace(scanner.Text()), armor.Header)
}

func Decrypt(input string, ids ...age.Identity) (string, error) {
	in := armor.NewReader(strings.NewReader(input))
	r, err := age.Decrypt(in, ids...)
	if err != nil {
		return input, err
	}
	var out bytes.Buffer
	if _, err = io.Copy(&out, r); err != nil {
		return input, err
	}
	return out.String(), nil
}

type armorWriterProxy struct {
	haveNewLine bool
	writer      io.Writer
}

var end = []byte("\n-----END")

func (w *armorWriterProxy) Write(p []byte) (n int, err error) {
	pLen := len(p)
	if pLen == 0 {
		return 0, nil
	}
	if len(p) > 8 && bytes.Compare(p[0:9], end) == 0 {
		if w.haveNewLine {
			p = p[1:]
		}
	} else {
		w.haveNewLine = p[pLen-1] == 10
	}
	return w.writer.Write(p)
}

func Encrypt(input string, rcpts ...age.Recipient) (string, error) {
	in := strings.NewReader(input)

	var out bytes.Buffer
	awp := &armorWriterProxy{false, &out}
	armorWriter := armor.NewWriter(awp)
	w, err := age.Encrypt(armorWriter, rcpts...)
	if err != nil {
		return input, err
	}

	if _, err := io.Copy(w, in); err != nil {
		return input, fmt.Errorf("can't encrypt : %w", err)
	}

	if err = w.Close(); err != nil {
		return input, fmt.Errorf("can't close encrypted output : %w", err)
	}

	if err = armorWriter.Close(); err != nil {
		return input, fmt.Errorf("can't close encrypted armor : %w", err)
	}

	return out.String(), nil
}
