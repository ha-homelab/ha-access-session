package main

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestMain(m *testing.M) {
	if os.Getenv("HA_ACCESS_TEST_MAIN") == "1" {
		main()
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func runCLI(t *testing.T, args ...string) (string, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, os.Args[0], args...)
	command.Env = append(os.Environ(), "HA_ACCESS_TEST_MAIN=1")
	output, err := command.CombinedOutput()
	if ctx.Err() != nil {
		t.Fatalf("CLI did not finish before starting a listener: %v", ctx.Err())
	}
	return string(output), err
}

func TestTLSFlagPairCheckedBeforeConfiguration(t *testing.T) {
	for _, flag := range []string{"-tls-cert", "-tls-key"} {
		t.Run(flag, func(t *testing.T) {
			missing := filepath.Join(t.TempDir(), "private-config-path.json")
			output, err := runCLI(t, "-config", missing, flag, "private-key-path.pem")
			if err == nil || !strings.Contains(output, "both tls-cert and tls-key are required") {
				t.Fatalf("want TLS pair failure before config access; output=%q, err=%v", output, err)
			}
			if strings.Contains(output, "configuration") || strings.Contains(output, "private-") {
				t.Fatalf("unexpected config access or private path in output: %q", output)
			}
		})
	}
}

func TestVersionDoesNotRequireConfigurationOrTLSKey(t *testing.T) {
	output, err := runCLI(t, "-version", "-config", "absent.json", "-tls-cert", "absent.pem")
	if err != nil || strings.TrimSpace(output) != version {
		t.Fatalf("want version without startup validation; output=%q, err=%v", output, err)
	}
}

func TestConfigurationOpenErrorCategoriesAreRedacted(t *testing.T) {
	for _, test := range []struct {
		cause    error
		category string
	}{
		{os.ErrNotExist, "not_found"},
		{os.ErrPermission, "permission_denied"},
		{errors.New("private underlying detail"), "open_failed"},
	} {
		t.Run(test.category, func(t *testing.T) {
			err := configurationOpenError(&os.PathError{Op: "open", Path: "private-config-path", Err: test.cause})
			want := "cannot open gateway configuration (" + test.category + ")"
			if err.Error() != want {
				t.Fatalf("got %q, want only %q", err, want)
			}
		})
	}
}

func TestMissingConfigurationCLIReportsOnlyCategory(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "private-config-path.json")
	output, err := runCLI(t, "-config", missing)
	if err == nil || !strings.Contains(output, "cannot open gateway configuration (not_found)") {
		t.Fatalf("want missing file category; output=%q, err=%v", output, err)
	}
	if strings.Contains(output, missing) {
		t.Fatalf("configuration path leaked: %q", output)
	}
}

func TestConfigurationJSONFailuresAreRedacted(t *testing.T) {
	for _, test := range []struct {
		name, body, category string
	}{
		{"empty", "", "invalid_json"},
		{"syntax", `{"origin": "private-json-value"`, "invalid_json"},
		{"unknown_field", `{"private_json_field": "private-json-value"}`, "invalid_json"},
		{"wrong_type", `{"origin": {"private_json_field": "private-json-value"}}`, "invalid_json"},
		{"second_value", `{"origin": "private-json-value"} {"private_json_field": 1}`, "trailing_data"},
		{"trailing_garbage", `{"origin": "private-json-value"} private-garbage`, "trailing_data"},
	} {
		t.Run(test.name, func(t *testing.T) {
			filename := filepath.Join(t.TempDir(), "private-config-path.json")
			if err := os.WriteFile(filename, []byte(test.body), 0600); err != nil {
				t.Fatal(err)
			}
			output, err := runCLI(t, "-config", filename)
			want := "invalid gateway configuration (" + test.category + ")"
			if err == nil || !strings.Contains(output, want) {
				t.Fatalf("want redacted parse failure %q; output=%q, err=%v", want, output, err)
			}
			if strings.Contains(output, "private") {
				t.Fatalf("private JSON detail or path leaked: %q", output)
			}
		})
	}
}

func TestValidConfigurationAllowsTrailingWhitespace(t *testing.T) {
	filename := filepath.Join(t.TempDir(), "gateway.json")
	if err := os.WriteFile(filename, []byte("{\"origin\":\"https://example.invalid\"}\n \t"), 0600); err != nil {
		t.Fatal(err)
	}
	config, err := loadConfiguration(filename)
	if err != nil || config.Origin != "https://example.invalid" {
		t.Fatalf("valid JSON changed: config=%+v err=%v", config, err)
	}
}
