package core_test

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

/*
	core.Log/Error/Warn/Debug are printf style, but go vet cannot check them: the printf
	analyzer only treats a registered function as formatting if its name ends in 'f'
	(Errorf, Logf...), and renaming the log API across the whole repo is not worth it.

	This test is the gate instead. It catches the specific footgun that actually happened
	(service.go leader election, fixed 2026-07-13): a log call whose format string has
	verbs but no arguments prints %!v(MISSING) at runtime -- exactly when someone is
	trying to read the error.
*/

func TestLogCallsWithVerbsHaveArgs(t *testing.T) {

	t.Parallel()

	// a qualified log call whose only argument is a string literal
	callRegex := regexp.MustCompile(`core\.(Log|Error|Warn|Debug)\(\s*"((?:[^"\\]|\\.)*)"\s*\)`)

	// a format verb, checked after stripping literal %% escapes
	verbRegex := regexp.MustCompile(`%[a-zA-Z]`)

	root := filepath.Join("..", "..")

	for _, dir := range []string{"modules", "cmd", "tools"} {

		err := filepath.WalkDir(filepath.Join(root, dir), func(path string, entry os.DirEntry, err error) error {

			if err != nil || entry.IsDir() || !strings.HasSuffix(path, ".go") {
				return err
			}

			data, err := os.ReadFile(path)
			if err != nil {
				return err
			}

			text := string(data)

			for _, match := range callRegex.FindAllStringSubmatchIndex(text, -1) {
				call := text[match[0]:match[1]]
				format := strings.ReplaceAll(text[match[4]:match[5]], "%%", "")
				if verbRegex.MatchString(format) {
					line := 1 + strings.Count(text[:match[0]], "\n")
					t.Errorf("log call has format verbs but no arguments: %s:%d: %s", path, line, call)
				}
			}

			return nil
		})

		if err != nil {
			t.Fatalf("failed to walk %s: %v", dir, err)
		}
	}
}
