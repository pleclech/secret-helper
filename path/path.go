package path

import (
	"fmt"
	"os"
)

// IsDir return error if path is not a directory
func IsDir(path string) error {
	info, err := os.Stat(path)
	if os.IsNotExist(err) {
		return err
	}
	if !info.IsDir() {
		return fmt.Errorf("%s is not a directory", path)
	}
	return nil
}

// IsFile return error if path is not a file
func IsFile(path string) error {
	info, err := os.Stat(path)
	if os.IsNotExist(err) {
		return err
	}
	if info.IsDir() {
		return fmt.Errorf("%s is not a file", path)
	}
	return nil
}
