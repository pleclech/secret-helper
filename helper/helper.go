package helper

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"

	log "github.com/sirupsen/logrus"
)

const (
	execModeAll = 0111
)

// ReadKey read a key from a file without empty line and # comment
func ReadAndClean(rd io.Reader) (string, error) {
	scanner := bufio.NewScanner(rd)

	var content bytes.Buffer
	for scanner.Scan() {
		tmp := scanner.Text()
		if len(tmp) == 0 || tmp[0] == '#' {
			continue
		}
		content.WriteString(tmp)
	}

	if err := scanner.Err(); err != nil {
		return "", fmt.Errorf("error reading key : %w", err)
	}

	return content.String(), nil
}

func SplitProtocol(src string) (protocol string, value string) {
	i := strings.Index(src, "://")
	if i <= 0 {
		return "", src
	}
	return src[:i], src[i+3:]
}

// ReaderFromProtocol return a reader from a file, env, string
// if a file is return you have to close it manually when done
func ReaderFromProtocol(prot string, name string) (*os.File, io.Reader, error) {
	switch prot {
	case "file":
		f, err := os.Open(name)
		if err != nil {
			return f, nil, err
		}
		return f, bufio.NewReader(f), nil
	case "env":
		tmp, ok := os.LookupEnv(name)
		if !ok {
			return nil, nil, fmt.Errorf("can't read key from env %q", name)
		}
		return nil, strings.NewReader(tmp), nil
	case "exe":
		stat, err := os.Stat(name)
		if err != nil {
			return nil, nil, fmt.Errorf("can't read key from executable %q : %w", name, err)
		}
		if (stat.Mode() & execModeAll) == 0 {
			return nil, nil, fmt.Errorf("can't read key from executable %q : %w", name, err)
		}
		var stderr bytes.Buffer
		var stdout bytes.Buffer
		cmd := exec.Command(name)
		cmd.Stdin = os.Stdin
		cmd.Stdout = &stdout
		cmd.Stderr = &stderr
		if err = cmd.Run(); err != nil {
			log.Errorf("%s", stderr.String())
			return nil, nil, fmt.Errorf("can't read key from executing %q : %w", name, err)
		}
		return nil, bytes.NewReader(stdout.Bytes()), nil
	case "raw", "":
		return nil, strings.NewReader(name), nil
	}
	return nil, nil, fmt.Errorf("unknown protocol %q for %q", prot, name)
}

func ReaderFromString(name string) (*os.File, io.Reader, error) {
	prot, name := SplitProtocol(name)
	return ReaderFromProtocol(prot, name)
}

func TruncateString(str string, num int) string {
	num -= 3
	if len(str) <= num {
		return str
	}
	return str[0:num] + "..."
}
