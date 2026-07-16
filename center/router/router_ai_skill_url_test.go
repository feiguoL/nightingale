package router

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"strings"
	"testing"

	"github.com/ccfos/nightingale/v6/aiagent/skill"
)

func TestGitHubURLToGitSource(t *testing.T) {
	tests := []struct {
		name      string
		rawURL    string
		wantOK    bool
		wantRef   string
		wantSubdir string
	}{
		{name: "tree with subdir", rawURL: "https://github.com/openclaw/agent-skills/tree/main/skills/demo", wantOK: true, wantRef: "main", wantSubdir: "skills/demo"},
		{name: "git suffix", rawURL: "https://github.com/openclaw/agent-skills.git", wantOK: true, wantRef: "main"},
		{name: "repo root not auto git", rawURL: "https://github.com/openclaw/agent-skills", wantOK: false},
		{name: "blob skill file handled as direct fetch", rawURL: "https://github.com/openclaw/agent-skills/blob/main/skills/demo/SKILL.md", wantOK: false},
	}
	for _, tt := range tests {
		cfg, _, ok, err := githubURLToGitSource(tt.rawURL)
		if err != nil {
			t.Fatalf("%s: unexpected err: %v", tt.name, err)
		}
		if ok != tt.wantOK {
			t.Fatalf("%s: ok=%v want %v", tt.name, ok, tt.wantOK)
		}
		if !ok {
			continue
		}
		if cfg.Ref != tt.wantRef || cfg.Subdir != tt.wantSubdir {
			t.Fatalf("%s: cfg=%+v", tt.name, cfg)
		}
	}
}

func TestParseImportedSkillContentMarkdown(t *testing.T) {
	content := "---\nname: demo\ndescription: test\n---\nDo the thing"
	meta, instructions, files, err := parseImportedSkillContent("https://example.com/SKILL.md", "text/markdown", []byte(content))
	if err != nil {
		t.Fatalf("parse markdown: %v", err)
	}
	if meta.Name != "demo" || instructions != "Do the thing" {
		t.Fatalf("unexpected parse result: meta=%+v instructions=%q", meta, instructions)
	}
	if files["SKILL.md"] != content {
		t.Fatalf("skill file missing: %+v", files)
	}
}

func TestParseImportedSkillContentTarGz(t *testing.T) {
	archive := buildTarGzSkillArchive(t, map[string]string{
		"SKILL.md": "---\nname: tar-demo\n---\nShip it",
		"notes.txt": "hello",
	})
	meta, instructions, files, err := parseImportedSkillContent("https://example.com/demo.tar.gz", "application/gzip", archive)
	if err != nil {
		t.Fatalf("parse archive: %v", err)
	}
	if meta.Name != "tar-demo" || instructions != "Ship it" {
		t.Fatalf("unexpected parse result: meta=%+v instructions=%q", meta, instructions)
	}
	if files["notes.txt"] != "hello" {
		t.Fatalf("archive file missing: %+v", files)
	}
}

func TestExtractGitHubURLFromHTML(t *testing.T) {
	body := `<a href="https://github.com/openclaw/agent-skills/tree/main/skills/demo">demo</a>`
	got, ok := extractGitHubURLFromHTML(body)
	if !ok {
		t.Fatalf("expected github url")
	}
	if got != "https://github.com/openclaw/agent-skills/tree/main/skills/demo" {
		t.Fatalf("unexpected github url: %q", got)
	}
}

func TestImportSkillFromURLUsesGitHubLinkFromRegistryHTML(t *testing.T) {
	oldFetchContent := fetchSkillURLContent
	oldFetchGit := fetchGitSkillForURLImport
	defer func() {
		fetchSkillURLContent = oldFetchContent
		fetchGitSkillForURLImport = oldFetchGit
	}()

	fetchSkillURLContent = func(ctx context.Context, rawURL string) (*fetchedSkillURLContent, error) {
		if !strings.Contains(rawURL, "skills.sh") {
			t.Fatalf("unexpected url: %s", rawURL)
		}
		return &fetchedSkillURLContent{
			URL:         rawURL,
			ContentType: "text/html",
			Data:        []byte(`<a href="https://github.com/openclaw/agent-skills/tree/main/skills/demo">demo</a>`),
		}, nil
	}
	fetchGitSkillForURLImport = func(ctx context.Context, cfg skill.GitConfig) (*skill.GitFetchResult, error) {
		if cfg.URL != "https://github.com/openclaw/agent-skills.git" || cfg.Ref != "main" || cfg.Subdir != "skills/demo" {
			t.Fatalf("unexpected cfg: %+v", cfg)
		}
		return &skill.GitFetchResult{
			Meta:         skill.Frontmatter{Name: "demo"},
			Instructions: "From git",
			Files:        map[string]string{"SKILL.md": "---\nname: demo\n---\nFrom git"},
			Commit:       "abc123",
		}, nil
	}

	result, err := importSkillFromURL(context.Background(), "https://www.skills.sh/obra/superpowers/brainstorming")
	if err != nil {
		t.Fatalf("import skill from registry html: %v", err)
	}
	if result.Meta.Name != "demo" || result.GitInfo == nil || result.GitInfo.CurrentCommit != "abc123" {
		t.Fatalf("unexpected import result: %+v", result)
	}
}

func buildTarGzSkillArchive(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	gzw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gzw)
	for name, content := range files {
		hdr := &tar.Header{Name: name, Mode: 0o644, Size: int64(len(content))}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatalf("write header: %v", err)
		}
		if _, err := tw.Write([]byte(content)); err != nil {
			t.Fatalf("write file: %v", err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("close tar: %v", err)
	}
	if err := gzw.Close(); err != nil {
		t.Fatalf("close gzip: %v", err)
	}
	return buf.Bytes()
}
