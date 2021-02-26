package crypt

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"

	"filippo.io/age"
	"github.com/pkg/errors"
	shage "github.com/pleclech/secret-helper/age"
	"github.com/pleclech/secret-helper/cleanup"
	"github.com/pleclech/secret-helper/editor"
	"github.com/pleclech/secret-helper/helper"
	"github.com/pleclech/secret-helper/vault"
	log "github.com/sirupsen/logrus"
)

const (
	VaultTag    = "!vault"
	AgeTag      = "!age"
	TripleQuote = "\"\"\""
)

var (
	reMLCryptEntry = regexp.MustCompile(`(?s)["]{3}(\n)(\s*)(!(age|vault)([^\n]*))(\n)(.+?)(["]{3})`)
	reSpaces       = regexp.MustCompile(`^(\s+)`)
)

type InputInfo struct {
	contentName string
	content     []byte
	contentType string
	fileMode    os.FileMode
	fileExt     string
	identities  []age.Identity
	recipients  []age.Recipient
	vaultKey    string
}

func (in InputInfo) TmpExt() string {
	if in.contentType != "" {
		return "." + in.contentType
	}
	return in.fileExt
}

func (in InputInfo) IsYaml() bool {
	return in.contentType == "yaml"
}

func (in InputInfo) IsCue() bool {
	return in.contentType == "cue"
}

func (in InputInfo) IsJson() bool {
	return in.contentType == "json"
}

func (in InputInfo) IsEnv() bool {
	return in.contentType == "env"
}

func (in InputInfo) Identities() []age.Identity {
	return in.identities
}

func (in InputInfo) Recipients() []age.Recipient {
	return in.recipients
}

func (in InputInfo) Validate() error {
	if len(in.vaultKey) == 0 && len(in.recipients) == 0 {
		return fmt.Errorf("no recipient or vault-key specified")
	}
	return nil
}

func (in InputInfo) ContentName() string {
	return in.contentName
}

func writeToFile(fileName string, content []byte, mode os.FileMode) error {
	tmpName := fileName + ".tmp"

	err := ioutil.WriteFile(tmpName, content, mode)
	if err != nil {
		return err
	}

	defer cleanup.Trap(func() { os.Remove(tmpName) })()

	return os.Rename(tmpName, fileName)
}

func (in InputInfo) Save(output string) error {
	switch output {
	case "", "-":
		fmt.Print(string(in.content))
		return nil
	}

	return writeToFile(output, in.content, in.fileMode)
}

func getContent(workingDir, source string) (content []byte, fileName string) {
	switch source {
	case "", "-":
		source = "-"
		var lines bytes.Buffer

		reader := bufio.NewReader(os.Stdin)
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				if err == io.EOF {
					lines.WriteString(line)
				}
				break
			}
			lines.WriteString(line)
		}
		content = lines.Bytes()
	default:
		fileName = source
		if in, err := ioutil.ReadFile(fileName); err == nil {
			content = in
			return
		}

		fileName = filepath.Join(workingDir, fileName)
		if in, err := ioutil.ReadFile(fileName); err == nil {
			content = in
			return
		}

		content = []byte(source)
		fileName = ""
	}

	return
}

func (in *InputInfo) Edit() error {
	if err := in.Decrypt(true); err != nil {
		return err
	}

	editedBytes, err := editor.CaptureInputFromEditor(
		editor.GetPreferredEditorFromEnvironment,
		in.content,
		in.TmpExt(),
	)
	if err != nil {
		return err
	}
	in.content = editedBytes

	return in.Encrypt()
}

func (inf *InputInfo) unmarshalYaml(encrypt bool) (*yaml.Node, error) {
	yn := &yaml.Node{}

	if err := yaml.Unmarshal(inf.content, yn); err != nil {
		return yn, err
	}

	inf.processYamlNode(yn, nil, -1, encrypt)
	return yn, nil
}

func (inf *InputInfo) processYamlNode(yn *yaml.Node, parent *yaml.Node, nodeIndex int, encrypt bool) {
	switch yn.Tag {
	case AgeTag:
		if encrypt {
			if !shage.MaybeEncrypted(yn.Value) {
				tmp, err := shage.Encrypt(yn.Value, inf.recipients...)
				if err != nil {
					err = fmt.Errorf("can't encrypt value <%s> : %w", helper.TruncateString(yn.Value, 4), err)
					log.Warn(err)
				} else {
					yn.Value = tmp
				}
			}
		} else {
			if shage.MaybeEncrypted(yn.Value) {
				tmp, err := shage.Decrypt(yn.Value, inf.identities...)
				if err != nil {
					err = fmt.Errorf("can't decrypt value <%s> : %w", helper.TruncateString(yn.Value, 64), err)
					log.Warn(err)
				} else {
					yn.Value = tmp
				}
			}
		}
	case VaultTag:
		if inf.vaultKey != "" {
			if encrypt {
				if !vault.MaybeEncrypted(yn.Value) {
					tmp, err := vault.Encrypt(yn.Value, inf.vaultKey, 0)
					if err != nil {
						err = fmt.Errorf("can't encrypt value <%s> : %w", helper.TruncateString(yn.Value, 4), err)
						log.Warn(err)
					} else {
						yn.Value = tmp
					}
				}
			} else {
				if vault.MaybeEncrypted(yn.Value) {
					tmp, err := vault.Decrypt(yn.Value, inf.vaultKey)
					if err != nil {
						err = fmt.Errorf("can't decrypt value <%s> : %w", helper.TruncateString(yn.Value, 64), err)
						log.Warn(err)
					} else {
						yn.Value = tmp
					}
				}
			}
		}
	}
	for i, n := range yn.Content {
		inf.processYamlNode(n, yn, i, encrypt)
	}
}

func (inf *InputInfo) encryptYaml() error {
	yn, err := inf.unmarshalYaml(true)
	if err != nil {
		return err
	}
	var tmp bytes.Buffer
	yamlEncoder := yaml.NewEncoder(&tmp)
	yamlEncoder.SetIndent(2)
	if err = yamlEncoder.Encode(yn); err != nil {
		return fmt.Errorf("can't encrypt yaml : %w", err)
	}

	inf.content = tmp.Bytes()

	return nil
}

type CryptBlock struct {
	Match     string
	Mode      string
	Spacing   string
	Value     string
	encrypted bool
}

func (cb CryptBlock) String(forEditing bool) string {
	value := cb.Value

	if cb.encrypted {
		value = strings.TrimSuffix(value, "\n")
	}

	if forEditing {
		value = strings.ReplaceAll(value, "\n", "\n"+cb.Spacing)
		return fmt.Sprintf("%s\n%s!%s\n%s%s\n%s%s", TripleQuote, cb.Spacing, cb.Mode, cb.Spacing, value, cb.Spacing, TripleQuote)
	} else {
		return fmt.Sprintf("%s%s%s", TripleQuote, value, TripleQuote)
	}
}

func (cb *CryptBlock) Decrypt(identities []age.Identity, vaultKey string) error {
	cb.encrypted = false
	switch cb.Mode {
	case "age":
		if !shage.MaybeEncrypted(cb.Value) {
			return nil
		}
		tmp, err := shage.Decrypt(cb.Value, identities...)
		if err != nil {
			cb.encrypted = true
			return err
		}
		cb.Value = tmp
	case "vault":
		if !vault.MaybeEncrypted(cb.Value) {
			cb.encrypted = true
			return nil
		}
		tmp, err := vault.Decrypt(cb.Value, vaultKey)
		if err != nil {
			return err
		}
		cb.Value = tmp
	default:
		return errors.Errorf("unknow crypt mode : %q", cb.Mode)
	}
	return nil
}

func (cb *CryptBlock) Encrypt(recipients []age.Recipient, vaultKey string) error {
	cb.encrypted = true
	switch cb.Mode {
	case "age":
		if shage.MaybeEncrypted(cb.Value) {
			return nil
		}
		tmp, err := shage.Encrypt(cb.Value, recipients...)
		if err != nil {
			cb.encrypted = false
			return err
		}
		cb.Value = tmp
	case "vault":
		if vault.MaybeEncrypted(cb.Value) {
			return nil
		}
		tmp, err := vault.Encrypt(cb.Value, vaultKey, 0)
		if err != nil {
			cb.encrypted = false
			return err
		}
		cb.Value = tmp
	default:
		return errors.Errorf("unknow crypt mode : %q", cb.Mode)
	}
	return nil
}

func NewCryptBlock(matches []string) *CryptBlock {
	ret := &CryptBlock{
		Match:   matches[0],
		Mode:    matches[4],
		Spacing: matches[2],
	}
	tmp := strings.ReplaceAll(matches[7], ret.Spacing, "")
	ret.Value = tmp[:len(tmp)-1]
	return ret
}

func (inf *InputInfo) encryptCue() error {
	content := string(inf.content)

	matches := reMLCryptEntry.FindAllStringSubmatch(content, -1)

	for _, match := range matches {
		cb := NewCryptBlock(match)
		err := cb.Encrypt(inf.recipients, inf.vaultKey)
		if err != nil {
			err = fmt.Errorf("can't encrypt value <%s> : %w", helper.TruncateString(cb.Value, 4), err)
			log.Warn(err)
		}
		content = strings.ReplaceAll(content, cb.Match, cb.String(true))
	}

	inf.content = []byte(content)
	return nil
}

func (inf *InputInfo) decryptCue(forEditing bool) error {
	content := string(inf.content)

	matches := reMLCryptEntry.FindAllStringSubmatch(content, -1)

	for _, match := range matches {
		cb := NewCryptBlock(match)
		err := cb.Decrypt(inf.identities, inf.vaultKey)
		if err != nil {
			err = fmt.Errorf("can't decrypt value <%s> : %w", helper.TruncateString(cb.Value, 64), err)
			log.Warn(err)
		}
		content = strings.ReplaceAll(content, cb.Match, cb.String(forEditing))
	}

	inf.content = []byte(content)
	return nil
}

func (inf *InputInfo) encryptEnv() error {
	content := string(inf.content)

	matches := reMLCryptEntry.FindAllStringSubmatch(content, -1)

	for _, match := range matches {
		cb := NewCryptBlock(match)
		err := cb.Encrypt(inf.recipients, inf.vaultKey)
		if err != nil {
			err = fmt.Errorf("can't encrypt value <%s> : %w", helper.TruncateString(cb.Value, 4), err)
			log.Warn(err)
		}
		content = strings.ReplaceAll(content, cb.Match, cb.String(true))
	}

	inf.content = []byte(content)
	return nil
}

func (inf *InputInfo) decryptEnv(forEditing bool) error {
	content := string(inf.content)

	matches := reMLCryptEntry.FindAllStringSubmatch(content, -1)

	for _, match := range matches {
		cb := NewCryptBlock(match)
		err := cb.Decrypt(inf.identities, inf.vaultKey)
		if err != nil {
			err = fmt.Errorf("can't decrypt value <%s> : %w", helper.TruncateString(cb.Value, 64), err)
			log.Warn(err)
		}
		content = strings.ReplaceAll(content, cb.Match, cb.String(forEditing))
	}

	inf.content = []byte(content)
	return nil
}

func (inf *InputInfo) decryptYaml() error {
	yn, err := inf.unmarshalYaml(false)
	if err != nil {
		return err
	}

	var tmp bytes.Buffer
	yamlEncoder := yaml.NewEncoder(&tmp)
	yamlEncoder.SetIndent(2)
	if err = yamlEncoder.Encode(yn); err != nil {
		return fmt.Errorf("can't decrypt yaml : %w", err)
	}

	inf.content = tmp.Bytes()

	return nil
}

// todo json
// raw file
func (inf *InputInfo) Encrypt() error {
	if inf.IsYaml() {
		return inf.encryptYaml()
	}
	if inf.IsCue() {
		return inf.encryptCue()
	}
	if inf.IsEnv() {
		return inf.encryptEnv()
	}
	if inf.IsJson() {
		return fmt.Errorf("json encryption not implemented")
	}
	return fmt.Errorf("raw encryption not implemented")
}

func (inf *InputInfo) Decrypt(forEditing bool) error {
	if inf.IsYaml() {
		return inf.decryptYaml()
	}
	if inf.IsCue() {
		return inf.decryptCue(forEditing)
	}
	if inf.IsEnv() {
		return inf.decryptEnv(forEditing)
	}
	if inf.IsJson() {
		return fmt.Errorf("json decryption not implemented")
	}
	return fmt.Errorf("raw decryption not implemented")
}

func NewInputInfo(workingDir string, input string, contentType string, privateKey string, publicKeys []string, vaultKey string) (*InputInfo, error) {
	content, contentName := getContent(workingDir, input)

	ret := &InputInfo{
		contentName: contentName,
		content:     content,
		contentType: contentType,
	}

	if len(privateKey) > 0 {
		ids, err := IdentitiesFromStrings(workingDir, []string{privateKey})
		if err != nil {
			return ret, err
		}
		ret.identities = ids
	}

	recipients, err := RecipientsFromStrings(workingDir, publicKeys)
	if err != nil {
		return ret, err
	}

	if len(ret.identities) > 0 {
		if recipient, ok := IdentityToRecipient(ret.identities[0]); ok {
			recipients = append(recipients, recipient)
		}
	}

	ret.recipients = recipients

	if contentName != "" {
		ret.fileExt = filepath.Ext(contentName)

		stat, _ := os.Stat(contentName)
		ret.fileMode = stat.Mode()
		if contentType == "" {
			if strings.Index(contentName, ".yaml") >= 0 || strings.Index(contentName, ".yml") >= 0 {
				ret.contentType = "yaml"
			} else if strings.Index(contentName, ".json") >= 0 {
				ret.contentType = "json"
			} else if strings.Index(contentName, ".cue") >= 0 {
				ret.contentType = "cue"
			} else if strings.Index(contentName, ".env") >= 0 {
				ret.contentType = "env"
			}
		}
	}

	if len(vaultKey) > 0 {
		if ret.contentType != "yaml" {
			return ret, fmt.Errorf("vault-key can only be specified for YAML content")
		}
		f, ior, err := helper.ReaderFromString(vaultKey)
		if f != nil {
			cleanup.TrapError(f.Close)
		}
		if err != nil {
			return ret, err
		}
		ret.vaultKey, err = helper.ReadAndClean(ior)
		if err != nil {
			return ret, err
		}
	}

	return ret, nil
}
