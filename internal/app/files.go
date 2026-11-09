package app

import (
	"errors"
	"os"
	"path/filepath"
)

func samePath(a, b string) bool {
	absA, errA := filepath.Abs(a)
	absB, errB := filepath.Abs(b)
	if errA == nil && errB == nil && absA == absB {
		return true
	}
	statA, errA := os.Stat(a)
	statB, errB := os.Stat(b)
	return errA == nil && errB == nil && os.SameFile(statA, statB)
}

func writeNew(path string, data []byte, mode os.FileMode) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	_, writeErr := file.Write(data)
	if writeErr == nil {
		writeErr = file.Sync()
	}
	closeErr := file.Close()
	if err := errors.Join(writeErr, closeErr); err != nil {
		return errors.Join(err, os.Remove(path))
	}
	return nil
}

func stageKey(path string, data []byte, mode os.FileMode) (string, error) {
	file, err := os.CreateTemp(filepath.Dir(path), ".key-*")
	if err != nil {
		return "", err
	}
	if err = file.Chmod(mode); err == nil {
		_, err = file.Write(data)
	}
	if err == nil {
		err = file.Sync()
	}
	err = errors.Join(err, file.Close())
	if err != nil {
		return "", errors.Join(err, os.Remove(file.Name()))
	}
	return file.Name(), nil
}

func replaceKeyPair(paths []string, data [][]byte) error {
	modes := []os.FileMode{0600, 0644}
	old := make([][]byte, len(paths))
	existed := make([]bool, len(paths))
	staged := make([]string, len(paths))
	defer func() {
		for _, path := range staged {
			if path != "" {
				os.Remove(path)
			}
		}
	}()
	for i, path := range paths {
		var err error
		old[i], err = os.ReadFile(path)
		if err != nil && !os.IsNotExist(err) {
			return err
		}
		existed[i] = err == nil
		staged[i], err = stageKey(path, data[i], modes[i])
		if err != nil {
			return err
		}
	}
	for i, path := range paths {
		if err := os.Rename(staged[i], path); err != nil {
			for j := i - 1; j >= 0; j-- {
				if !existed[j] {
					err = errors.Join(err, os.Remove(paths[j]))
					continue
				}
				backup, restoreErr := stageKey(paths[j], old[j], modes[j])
				if restoreErr == nil {
					restoreErr = os.Rename(backup, paths[j])
					os.Remove(backup)
				}
				err = errors.Join(err, restoreErr)
			}
			return err
		}
	}
	return nil
}
