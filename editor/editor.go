package editor

import (
	"io/ioutil"
	"os"
	"os/exec"
	"strings"

	"github.com/pleclech/secret-helper/cleanup"
)

type PreferredEditorResolver func() string

func GetPreferredEditorFromEnvironment() string {
	editor := os.Getenv("EDITOR")

	if editor == "" {
		return DefaultEditor
	}

	return editor
}

func resolveEditorArguments(executable string, filename string) []string {
	args := []string{filename}
	if strings.Contains(executable, "Visual Studio Code.app") || strings.Contains(executable, "vscode") || strings.Contains(executable, "VS Code") {
		args = append([]string{"--wait"}, args...)
		return args
	}

	return args
}

// OpenFileInEditor opens filename in a text editor.
func OpenFileInEditor(filename string, resolveEditor PreferredEditorResolver) error {
	// Get the full executable path for the editor.
	editor := resolveEditor()
	args := strings.Fields(editor)
	editor = args[0]

	executable, err := exec.LookPath(editor)
	if err != nil {
		return err
	}

	args = append(args[1:], resolveEditorArguments(executable, filename)...)

	cmd := exec.Command(executable, args...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	return cmd.Run()
}

// CaptureInputFromEditor opens a temporary file in a text editor and returns
// the written bytes on success or an error on failure. It handles deletion
// of the temporary file behind the scenes.
func CaptureInputFromEditor(resolveEditor PreferredEditorResolver, initialContent []byte, fileExt string) ([]byte, error) {
	file, err := ioutil.TempFile(os.TempDir(), "*"+fileExt)
	if err != nil {
		return []byte{}, err
	}

	filename := file.Name()

	// Defer removal of the temporary file in case any of the next steps fail.
	defer cleanup.Trap(func() { os.Remove(filename) })()

	if len(initialContent) != 0 {
		if _, err = file.Write(initialContent); err != nil {
			return []byte{}, err
		}
	}

	if err = file.Close(); err != nil {
		return []byte{}, err
	}

	if err = OpenFileInEditor(filename, resolveEditor); err != nil {
		return []byte{}, err
	}

	bytes, err := ioutil.ReadFile(filename)
	if err != nil {
		return []byte{}, err
	}

	return bytes, nil
}
