package router

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/ccfos/nightingale/v6/aiagent/skill"
	"github.com/ccfos/nightingale/v6/models"
	"github.com/ccfos/nightingale/v6/pkg/ginx"

	"github.com/gin-gonic/gin"
)

const maxSkillURLImportSize = 10 * 1024 * 1024

var githubRepoURLPattern = regexp.MustCompile(`https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(?:\.git)?(?:/[^"]*)?`)

var fetchSkillURLContent = defaultFetchSkillURLContent
var fetchGitSkillForURLImport = fetchGitSkillWithTimeout

type aiSkillURLImportRequest struct {
	URL          string  `json:"url"`
	Private      *int    `json:"private"`
	UserGroupIds []int64 `json:"user_group_ids"`
}

type aiSkillURLImportResult struct {
	Meta         skill.Frontmatter
	Instructions string
	Files        map[string]string
	GitInfo      *models.AISkillGitInfo
}

type fetchedSkillURLContent struct {
	URL         string
	ContentType string
	Data        []byte
}

func (rt *Router) aiSkillURLImport(c *gin.Context) {
	var req aiSkillURLImportRequest
	ginx.BindJSON(c, &req)

	me := c.MustGet("user").(*models.User)
	auth := rt.resolveSkillAuth(c, req.Private, req.UserGroupIds, nil, req.UserGroupIds)
	result, err := importSkillFromURL(c.Request.Context(), strings.TrimSpace(req.URL))
	ginx.Dangerous(err)

	id, err := rt.doSkillImport(result.Meta, result.Instructions, result.Files, me.Username, result.GitInfo, &auth)
	ginx.Dangerous(err)
	ginx.NewRender(c).Data(id, nil)
}

func importSkillFromURL(ctx context.Context, rawURL string) (*aiSkillURLImportResult, error) {
	return importSkillFromURLDepth(ctx, rawURL, 0)
}

func importSkillFromURLDepth(ctx context.Context, rawURL string, depth int) (*aiSkillURLImportResult, error) {
	if depth > 2 {
		return nil, fmt.Errorf("url import redirect chain is too deep")
	}
	rawURL = strings.TrimSpace(rawURL)
	if rawURL == "" {
		return nil, fmt.Errorf("url is required")
	}

	if gitCfg, fields, ok, err := githubURLToGitSource(rawURL); err != nil {
		return nil, err
	} else if ok {
		result, err := fetchGitSkillForURLImport(ctx, gitCfg)
		if err != nil {
			return nil, err
		}
		fields.Commit = result.Commit
		return &aiSkillURLImportResult{
			Meta:         result.Meta,
			Instructions: result.Instructions,
			Files:        result.Files,
			GitInfo:      aiSkillGitInfoFromFields(fields),
		}, nil
	}

	content, err := fetchSkillURLContent(ctx, rawURL)
	if err != nil {
		return nil, err
	}
	if shouldResolveRegistryHTML(content.URL, content.ContentType) {
		if githubURL, ok := extractGitHubURLFromHTML(string(content.Data)); ok {
			return importSkillFromURLDepth(ctx, githubURL, depth+1)
		}
	}

	meta, instructions, files, err := parseImportedSkillContent(content.URL, content.ContentType, content.Data)
	if err != nil {
		return nil, err
	}
	return &aiSkillURLImportResult{Meta: meta, Instructions: instructions, Files: files}, nil
}

func defaultFetchSkillURLContent(ctx context.Context, rawURL string) (*fetchedSkillURLContent, error) {
	u, err := validateSkillImportURL(rawURL)
	if err != nil {
		return nil, err
	}

	transport := &http.Transport{DialContext: skillImportSafeDialContext}
	client := &http.Client{
		Timeout:   20 * time.Second,
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return fmt.Errorf("too many redirects")
			}
			_, err := validateSkillImportURL(req.URL.String())
			return err
		},
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "text/markdown,text/plain,application/zip,application/gzip,application/octet-stream,text/html;q=0.8,*/*;q=0.5")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("fetch skill url failed: %s", resp.Status)
	}
	if resp.ContentLength > maxSkillURLImportSize {
		return nil, fmt.Errorf("remote content exceeds 10MB limit")
	}

	data, err := io.ReadAll(io.LimitReader(resp.Body, maxSkillURLImportSize+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxSkillURLImportSize {
		return nil, fmt.Errorf("remote content exceeds 10MB limit")
	}

	return &fetchedSkillURLContent{
		URL:         resp.Request.URL.String(),
		ContentType: resp.Header.Get("Content-Type"),
		Data:        data,
	}, nil
}

func validateSkillImportURL(rawURL string) (*url.URL, error) {
	u, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil {
		return nil, fmt.Errorf("invalid url: %w", err)
	}
	if u.Scheme != "https" {
		return nil, fmt.Errorf("url must use https")
	}
	if u.Host == "" {
		return nil, fmt.Errorf("url has no host")
	}
	return u, nil
}

func githubURLToGitSource(rawURL string) (skill.GitConfig, aiSkillGitFields, bool, error) {
	u, err := validateSkillImportURL(rawURL)
	if err != nil {
		return skill.GitConfig{}, aiSkillGitFields{}, false, err
	}
	host := strings.ToLower(u.Hostname())
	if host != "github.com" && host != "www.github.com" {
		return skill.GitConfig{}, aiSkillGitFields{}, false, nil
	}
	parts := splitURLPath(u.Path)
	if len(parts) < 2 {
		return skill.GitConfig{}, aiSkillGitFields{}, false, fmt.Errorf("github url must include owner and repository")
	}
	owner := parts[0]
	repo := strings.TrimSuffix(parts[1], ".git")
	baseURL := fmt.Sprintf("https://github.com/%s/%s.git", owner, repo)
	if len(parts) == 2 && strings.HasSuffix(strings.ToLower(u.Path), ".git") {
		cfg := skill.GitConfig{URL: baseURL, RefType: skill.GitRefBranch, Ref: "main", AuthType: skill.GitAuthNone}
		return cfg, aiSkillGitFields{URL: cfg.URL, RefType: cfg.RefType, Ref: cfg.Ref, AuthType: cfg.AuthType}, true, nil
	}
	if len(parts) < 3 {
		return skill.GitConfig{}, aiSkillGitFields{}, false, nil
	}
	if parts[2] == "tree" {
		if len(parts) < 4 {
			return skill.GitConfig{}, aiSkillGitFields{}, false, fmt.Errorf("github tree url must include branch")
		}
		cfg := skill.GitConfig{
			URL:      baseURL,
			RefType:  skill.GitRefBranch,
			Ref:      parts[3],
			AuthType: skill.GitAuthNone,
			Subdir:   strings.Join(parts[4:], "/"),
		}
		return cfg, aiSkillGitFields{URL: cfg.URL, RefType: cfg.RefType, Ref: cfg.Ref, AuthType: cfg.AuthType, Subdir: cfg.Subdir}, true, nil
	}
	if parts[2] == "blob" {
		if len(parts) < 5 || !strings.EqualFold(parts[len(parts)-1], "SKILL.md") {
			return skill.GitConfig{}, aiSkillGitFields{}, false, nil
		}
		return skill.GitConfig{}, aiSkillGitFields{}, false, nil
	}
	if strings.HasSuffix(strings.ToLower(u.Path), ".git") {
		cfg := skill.GitConfig{URL: u.String(), RefType: skill.GitRefBranch, Ref: "main", AuthType: skill.GitAuthNone}
		return cfg, aiSkillGitFields{URL: cfg.URL, RefType: cfg.RefType, Ref: cfg.Ref, AuthType: cfg.AuthType}, true, nil
	}
	return skill.GitConfig{}, aiSkillGitFields{}, false, nil
}

func parseImportedSkillContent(rawURL, contentType string, data []byte) (skill.Frontmatter, string, map[string]string, error) {
	lowerURL := strings.ToLower(rawURL)
	contentType = strings.ToLower(strings.TrimSpace(strings.Split(contentType, ";")[0]))

	if looksLikeArchive(lowerURL, contentType) {
		return extractSkillArchiveData(rawURL, data)
	}

	text := string(data)
	meta, instructions, ok := skill.ParseMarkdown(text)
	if ok {
		m := models.AISkill{Name: meta.Name, Instructions: instructions}
		if err := m.Verify(); err != nil {
			return skill.Frontmatter{}, "", nil, err
		}
		return meta, instructions, map[string]string{"SKILL.md": text}, nil
	}

	if strings.Contains(contentType, "html") {
		return skill.Frontmatter{}, "", nil, fmt.Errorf("url page does not expose an importable skill artifact")
	}
	return skill.Frontmatter{}, "", nil, fmt.Errorf("url does not contain a valid SKILL.md or supported archive")
}

func extractSkillArchiveData(rawURL string, data []byte) (skill.Frontmatter, string, map[string]string, error) {
	tmpDir, err := os.MkdirTemp("", "skill-url-import-*")
	if err != nil {
		return skill.Frontmatter{}, "", nil, err
	}
	defer os.RemoveAll(tmpDir)

	lowerURL := strings.ToLower(rawURL)
	if strings.HasSuffix(lowerURL, ".zip") {
		err = skill.ExtractZip(data, tmpDir)
	} else {
		err = skill.ExtractTarGz(bytes.NewReader(data), tmpDir)
	}
	if err != nil {
		return skill.Frontmatter{}, "", nil, err
	}

	files, err := skill.Walk(tmpDir)
	if err != nil {
		return skill.Frontmatter{}, "", nil, err
	}
	skillMD, ok := files["SKILL.md"]
	if !ok || strings.TrimSpace(skillMD) == "" {
		return skill.Frontmatter{}, "", nil, fmt.Errorf("SKILL.md not found in archive root")
	}
	meta, instructions, ok := skill.ParseMarkdown(skillMD)
	if !ok {
		return skill.Frontmatter{}, "", nil, fmt.Errorf("SKILL.md must contain valid YAML frontmatter with a non-empty 'name' field")
	}
	m := models.AISkill{Name: meta.Name, Instructions: instructions}
	if err := m.Verify(); err != nil {
		return skill.Frontmatter{}, "", nil, err
	}
	return meta, instructions, files, nil
}

func looksLikeArchive(rawURL, contentType string) bool {
	if strings.HasSuffix(rawURL, ".zip") || strings.HasSuffix(rawURL, ".tar.gz") || strings.HasSuffix(rawURL, ".tgz") {
		return true
	}
	return strings.Contains(contentType, "zip") || strings.Contains(contentType, "gzip") || strings.Contains(contentType, "x-gzip")
}

func shouldResolveRegistryHTML(rawURL, contentType string) bool {
	if !strings.Contains(strings.ToLower(contentType), "html") {
		return false
	}
	host := strings.ToLower(hostname(rawURL))
	return host == "clawhub.ai" || host == "www.clawhub.ai" || host == "skills.sh" || host == "www.skills.sh"
}

func extractGitHubURLFromHTML(body string) (string, bool) {
	match := githubRepoURLPattern.FindString(body)
	if match == "" {
		return "", false
	}
	return strings.TrimRight(match, `"'.,)`), true
}

func splitURLPath(p string) []string {
	parts := strings.Split(strings.Trim(strings.TrimSpace(p), "/"), "/")
	ret := make([]string, 0, len(parts))
	for _, part := range parts {
		if part = strings.TrimSpace(part); part != "" {
			ret = append(ret, part)
		}
	}
	return ret
}

func hostname(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	return u.Hostname()
}

func skillImportSafeDialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("dns lookup failed for %s: %v", host, err)
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("no addresses for %s", host)
	}
	for _, ip := range ips {
		if !skillImportPublicIP(ip.IP) {
			return nil, fmt.Errorf("blocked: %s resolves to non-public address %s", host, ip.IP.String())
		}
	}
	d := net.Dialer{Timeout: 5 * time.Second}
	return d.DialContext(ctx, network, net.JoinHostPort(ips[0].IP.String(), port))
}

func skillImportPublicIP(ip net.IP) bool {
	if ip == nil || ip.IsUnspecified() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsMulticast() || ip.IsPrivate() {
		return false
	}
	if ip4 := ip.To4(); ip4 != nil {
		if ip4[0] == 100 && ip4[1] >= 64 && ip4[1] <= 127 {
			return false
		}
		if ip4[0] == 192 && ip4[1] == 0 && ip4[2] == 0 {
			return false
		}
		if ip4[0] == 192 && ip4[1] == 0 && ip4[2] == 2 {
			return false
		}
		if ip4[0] == 198 && ip4[1] == 51 && ip4[2] == 100 {
			return false
		}
		if ip4[0] == 203 && ip4[1] == 0 && ip4[2] == 113 {
			return false
		}
		if ip4[0] == 198 && (ip4[1] == 18 || ip4[1] == 19) {
			return false
		}
		if ip4[0] >= 240 {
			return false
		}
	}
	return true
}
