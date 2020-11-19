package crypt

import (
	"fmt"
	"path/filepath"
	"reflect"
	"strings"

	"filippo.io/age"
	"filippo.io/age/agessh"
	"github.com/pleclech/secret-helper/cleanup"
	"github.com/pleclech/secret-helper/helper"
	"github.com/pleclech/secret-helper/path"
	"golang.org/x/crypto/ssh"
)

func ParsePublicKey(arg string) (recipient age.Recipient, err error) {
	f, rd, err := helper.ReaderFromString(arg)
	if f != nil {
		defer cleanup.TrapError(f.Close)
	}
	if err != nil {
		return nil, err
	}

	arg, err = helper.ReadAndClean(rd)
	if err != nil {
		return
	}

	switch {
	case strings.HasPrefix(arg, "age1"):
		return age.ParseX25519Recipient(arg)
	case strings.HasPrefix(arg, "ssh-"):
		return agessh.ParseRecipient(arg)
	}

	return nil, fmt.Errorf("unknown public key type: %q", arg)
}

func ParsePrivateKey(arg string) ([]age.Identity, error) {
	f, rd, err := helper.ReaderFromString(arg)
	if f != nil {
		defer cleanup.TrapError(f.Close)
	}
	if err != nil {
		return nil, err
	}
	ids, err := age.ParseIdentities(rd)
	if err != nil {
		return nil, fmt.Errorf("unknown private key type: %w", err)
	}
	return ids, nil
}

func getPublicKey(x interface{}) (ssh.PublicKey, bool) {
	v := reflect.ValueOf(x).Elem().FieldByName("sshKey")
	key, ok := v.Interface().(ssh.PublicKey)
	return key, ok
}

func IdentityToRecipient(id age.Identity) (age.Recipient, bool) {
	if k, ok := id.(*age.X25519Identity); ok {
		return k.Recipient(), true
	}

	if k, ok := id.(*agessh.RSAIdentity); ok {
		if pubKey, ok := getPublicKey(*k); ok {
			if rcpt, err := agessh.NewRSARecipient(pubKey); err == nil {
				return rcpt, true
			}
		}
	}

	if k, ok := id.(*agessh.Ed25519Identity); ok {
		if pubKey, ok := getPublicKey(*k); ok {
			if rcpt, err := agessh.NewEd25519Recipient(pubKey); err == nil {
				return rcpt, true
			}
		}
	}

	return nil, false
}

func IdentitiesFromStrings(workingDir string, keys []string) (ret []age.Identity, err error) {
	var ids []age.Identity
	for _, key := range keys {
		prot, fileName := helper.SplitProtocol(key)
		if prot == "file" {
			if path.IsFile(fileName) != nil {
				fileName = filepath.Join(workingDir, key)
				if path.IsFile(fileName) != nil {
					fileName = key
				}
			}
		}
		if ids, err = ParsePrivateKey(prot + "://" + fileName); err != nil {
			return
		}
		ret = append(ret, ids...)
	}
	return
}

func RecipientsFromStrings(workingDir string, keys []string) (ret []age.Recipient, err error) {
	var rcpt age.Recipient
	for _, key := range keys {
		prot, fileName := helper.SplitProtocol(key)
		if prot == "file" {
			if path.IsFile(fileName) != nil {
				fileName = filepath.Join(workingDir, key)
				if path.IsFile(fileName) != nil {
					fileName = key
				}
			}
		}
		if rcpt, err = ParsePublicKey(prot + "://" + fileName); err != nil {
			return
		}
		ret = append(ret, rcpt)
	}
	return
}
