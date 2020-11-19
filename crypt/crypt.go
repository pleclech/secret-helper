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
	"filippo.io/age/armor"
	shage "github.com/pleclech/secret-helper/age"
	"github.com/pleclech/secret-helper/cleanup"
	"github.com/pleclech/secret-helper/editor"
	"github.com/pleclech/secret-helper/helper"
	"github.com/pleclech/secret-helper/vault"
	log "github.com/sirupsen/logrus"
)

const (
	VaultTag = "!vault"
	AgeTag   = "!age"
)

var (
	reYamlAgeEntry = regexp.MustCompile(`([^\S\r\n]*)(\w+):(\s+)[!]age(.*)[\||>].*`)
	reYamlAgeArmor = regexp.MustCompile(`(?s)(\n*)(\s*)(-{5}BEGIN AGE ENCRYPTED FILE-{5}(.+?)(\s+?)-{5}END AGE ENCRYPTED FILE-{5})`)
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

func (in InputInfo) IsJson() bool {
	return in.contentType == "json"
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
	if err := in.Decrypt(); err != nil {
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

func padd(source string, paddLen int) string {
	var buf bytes.Buffer
	padd := fmt.Sprintf("%%%ds", paddLen)
	padd = fmt.Sprintf(padd, " ")
	lines := strings.Split(source, "\n")
	ln := len(lines) - 2
	for i, line := range lines {
		buf.WriteString(padd)
		buf.WriteString(line)
		if i < ln {
			buf.WriteRune('\n')
		}
	}
	return buf.String()
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
					log.Warnf("can't encrypt value <%s> : %w", helper.TruncateString(yn.Value, 64), err)
				} else {
					yn.Value = tmp
				}
			}
		} else {
			if shage.MaybeEncrypted(yn.Value) {
				tmp, err := shage.Decrypt(yn.Value, inf.identities...)
				if err != nil {
					log.Warnf("can't decrypt value <%s> : %w", helper.TruncateString(yn.Value, 64), err)
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
						log.Warnf("can't encrypt value <%s> : %w", helper.TruncateString(yn.Value, 64), err)
					} else {
						yn.Value = tmp
					}
				}
			} else {
				if vault.MaybeEncrypted(yn.Value) {
					tmp, err := vault.Decrypt(yn.Value, inf.vaultKey)
					if err != nil {
						log.Warnf("can't decrypt value <%s> : %w", helper.TruncateString(yn.Value, 64), err)
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

	content := string(inf.content)

	matches := reYamlAgeEntry.FindAllStringSubmatch(content, -1)
doCrypt:
	for _, match := range matches {
		spaceLen := len(match[1])
		pat := fmt.Sprintf(`%s(((\s{%d,})(.+))+)`, regexp.QuoteMeta(match[0]), spaceLen+2)
		reN := regexp.MustCompile(pat)
		values := reN.FindAllStringSubmatch(content, -1)
		if len(values) > 0 {
			value := values[0][1]
			var bb bytes.Buffer
			sep := ""
			for i, tmp := range strings.Split(value[1:], "\n") {
				tmp = strings.TrimSpace(tmp)
				if i == 0 && strings.HasPrefix(tmp, armor.Header) {
					continue doCrypt
				}
				bb.WriteString(sep)
				bb.WriteString(tmp)
				sep = "\n"
			}

			in := bytes.NewReader(bb.Bytes())

			var out bytes.Buffer
			armorWriter := armor.NewWriter(&out)
			w, err := age.Encrypt(armorWriter, inf.recipients...)
			if err != nil {
				return err
			}

			if _, err := io.Copy(w, in); err != nil {
				return fmt.Errorf("can't encrypt : %w", err)
			}

			if err = w.Close(); err != nil {
				return fmt.Errorf("can't close encrypted output : %w", err)
			}

			if err = armorWriter.Close(); err != nil {
				return fmt.Errorf("can't close encrypted armor : %w", err)
			}

			decValue := strings.TrimRight(padd(out.String(), spaceLen+2), " ")
			content = strings.Replace(content, value, "\n"+decValue, -1)
		}
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
	return fmt.Errorf("raw encryption not implemented")
}

func (inf *InputInfo) Decrypt() error {
	if inf.IsYaml() {
		return inf.decryptYaml()
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
