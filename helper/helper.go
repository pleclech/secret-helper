package helper

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	log "github.com/sirupsen/logrus"
)

const (
	execModeAll = 0111
)

// ReadKey read a key from a file without empty line and # comment
func ReadAndClean(rd io.Reader, keepNewLine bool) (string, error) {
	scanner := bufio.NewScanner(rd)

	var content bytes.Buffer
	sep := ""
	for scanner.Scan() {
		tmp := scanner.Text()
		if len(tmp) == 0 || tmp[0] == '#' {
			continue
		}
		content.WriteString(tmp)
		content.WriteString(sep)
		if keepNewLine {
			sep = "\n"
		}
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
func ReaderFromProtocol(prot string, name string) (io.Closer, *bufio.Reader, error) {
	switch prot {
	case "file":
		if len(name) > 0 && name[0:1] == "~" {
			home, err := os.UserHomeDir()
			if err != nil {
				return nil, nil, err
			}
			name = filepath.Join(home, name[1:])
		}
		f, err := os.Open(name)
		if err != nil {
			return f, nil, err
		}
		return f, bufio.NewReader(f), nil
	case "http", "https":
		client := http.Client{}
		tmp := strings.Split(name, "@@")
		name = tmp[0]
		resp, err := client.Get(prot + "://" + name)
		if err != nil {
			return nil, nil, err
		}
		body := resp.Body
		return body, bufio.NewReader(body), nil
	case "env":
		tmp, ok := os.LookupEnv(name)
		if !ok {
			return nil, nil, fmt.Errorf("can't read key from env %q", name)
		}
		return nil, bufio.NewReader(strings.NewReader(tmp)), nil
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
		return nil, bufio.NewReader(bytes.NewReader(stdout.Bytes())), nil
	case "raw", "":
		return nil, bufio.NewReader(strings.NewReader(name)), nil
	}
	return nil, nil, fmt.Errorf("unknown protocol %q for %q", prot, name)
}

func ReaderFromString(name string) (io.Closer, *bufio.Reader, error) {
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
