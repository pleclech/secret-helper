package crypt

import (
	"crypto/ed25519"
	"crypto/rsa"
	"fmt"
	"io"
	"path/filepath"
	"regexp"
	"strings"

	"filippo.io/age"
	"filippo.io/age/agessh"
	"github.com/pleclech/secret-helper/cleanup"
	"github.com/pleclech/secret-helper/helper"
	"github.com/pleclech/secret-helper/path"
	"golang.org/x/crypto/ssh"
)

func SSHParseIdentity(pemBytes []byte) (age.Identity, age.Recipient, error) {
	k, err := ssh.ParseRawPrivateKey(pemBytes)
	if err != nil {
		return nil, nil, err
	}

	switch k := k.(type) {
	case *ed25519.PrivateKey:
		id, err := agessh.NewEd25519Identity(*k)
		if err != nil {
			return id, nil, err
		}
		s, err := ssh.NewSignerFromKey(k)
		if err != nil {
			return id, nil, err
		}
		rcpt, err := agessh.NewEd25519Recipient(s.PublicKey())
		if err != nil {
			return id, nil, err
		}
		return id, rcpt, nil
	case *rsa.PrivateKey:
		id, err := agessh.NewRSAIdentity(k)
		if err != nil {
			return id, nil, err
		}
		s, err := ssh.NewSignerFromKey(k)
		if err != nil {
			return id, nil, err
		}
		rcpt, err := agessh.NewRSARecipient(s.PublicKey())
		if err != nil {
			return id, nil, err
		}
		return id, rcpt, nil
	}

	return nil, nil, fmt.Errorf("unsupported SSH identity type: %T", k)
}

func voidFilter(arg string) bool {
	return true
}

func ParsePublicKey(arg string) (recipients []age.Recipient, err error) {
	filter := voidFilter
	_, fn := helper.SplitProtocol(arg)
	tmp := strings.Split(fn, "@@")
	if len(tmp) == 2 {
		fnArgs := strings.Split(tmp[1], ":")
		switch fnArgs[0] {
		case "match":
			reMatch, err := regexp.Compile("(?m)(" + fnArgs[1] + ")")
			if err != nil {
				return nil, fmt.Errorf("can't parse matching re : %w", err)
			}
			filter = func(arg string) bool {
				return reMatch.MatchString(arg)
			}
		}
	}
	f, rd, err := helper.ReaderFromString(arg)
	if f != nil {
		defer cleanup.TrapError(f.Close)
	}
	if err != nil {
		return nil, err
	}

	var key string
	key, err = rd.ReadString('\n')
	for len(key) > 0 {
		if !filter(key) {
			key, err = rd.ReadString('\n')
			continue
		}
		switch {
		case strings.HasPrefix(key, "age1"):
			rcpt, err := age.ParseX25519Recipient(key)
			if err != nil {
				return nil, err
			}
			recipients = append(recipients, rcpt)
		case strings.HasPrefix(key, "ssh-"):
			rcpt, err := agessh.ParseRecipient(key)
			if err != nil {
				return nil, err
			}
			recipients = append(recipients, rcpt)
		}
		key, err = rd.ReadString('\n')
	}
	if err == io.EOF {
		err = nil
	}
	return
}

func ParsePrivateKey(arg string) ([]age.Identity, []age.Recipient, error) {
	f, rd, err := helper.ReaderFromString(arg)

	if f != nil {
		defer cleanup.TrapError(f.Close)
	}

	if err != nil {
		return nil, nil, err
	}

	if val, err := rd.Peek(10); err == nil {
		if string(val) == "-----BEGIN" {
			if val, err = rd.ReadBytes(0); err != io.EOF {
				return nil, nil, fmt.Errorf("can't read ssh private key: %w", err)
			}
			id, rcpt, err := SSHParseIdentity(val)
			if err != nil {
				return nil, nil, fmt.Errorf("can't read ssh private key: %w", err)
			}
			return []age.Identity{id}, []age.Recipient{rcpt}, nil
		}
	}

	ids, err := age.ParseIdentities(rd)
	if err != nil {
		return nil, nil, fmt.Errorf("unknown private key type: %w", err)
	}
	var recipients []age.Recipient
	for _, id := range ids {
		if k, ok := id.(*age.X25519Identity); ok {
			recipients = append(recipients, k.Recipient())
		}
	}
	return ids, recipients, nil
}

func IdentitiesFromStrings(workingDir string, keys []string) (ids []age.Identity, recipients []age.Recipient, err error) {
	var tmpIDs []age.Identity
	var tmpRecipients []age.Recipient
	for _, key := range keys {
		prot, fileName := helper.SplitProtocol(key)
		if prot == "file" {
			if path.IsFile(fileName) != nil {
				tmp := filepath.Join(workingDir, fileName)
				if path.IsFile(tmp) == nil {
					fileName = tmp
				}
			}
		}
		if tmpIDs, tmpRecipients, err = ParsePrivateKey(prot + "://" + fileName); err != nil {
			return
		}
		ids = append(ids, tmpIDs...)
		recipients = append(recipients, tmpRecipients...)
	}
	return
}

func RecipientsFromStrings(workingDir string, keys []string) (ret []age.Recipient, err error) {
	var rcpts []age.Recipient
	for _, key := range keys {
		prot, fileName := helper.SplitProtocol(key)
		if prot == "file" {
			if path.IsFile(fileName) != nil {
				tmp := filepath.Join(workingDir, fileName)
				if path.IsFile(tmp) == nil {
					fileName = tmp
				}
			}
		}
		if rcpts, err = ParsePublicKey(prot + "://" + fileName); err != nil {
			return
		}
		ret = append(ret, rcpts...)
	}
	return
}
