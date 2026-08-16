package util

import (
	"os"
	"path/filepath"
)

func GetExeDir() (string, error) {
	exePath, err := os.Executable()
	if err != nil {
		return "", err
	}
	realPath, err := filepath.EvalSymlinks(exePath)
	if err != nil {
		return "", err
	}
	return filepath.Dir(realPath), nil
}
