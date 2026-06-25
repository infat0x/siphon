package collector

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"siphon-go/core"
	"strings"
	"time"
)

func runCmdLines(ctx context.Context, name string, args ...string) []string {
	cmd := exec.CommandContext(ctx, name, args...)
	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	_ = cmd.Run()
	var res []string
	for _, l := range strings.Split(stdout.String(), "\n") {
		l = strings.TrimSpace(l)
		if strings.HasPrefix(l, "http") {
			res = append(res, l)
		}
	}
	return res
}

func RunGau(host string) []string {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	bare := core.BareDomain(host)
	return runCmdLines(ctx, "gau", "--providers", "wayback,commoncrawl,otx,urlscan", "--threads", "5", "--blacklist", "ttf,woff,woff2,eot,svg,png,jpg,jpeg,gif,ico,css,pdf,mp4,mp3,zip", bare)
}

func RunKatana(url string) []string {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	args := []string{"-u", url, "-jc", "-kf", "all", "-aff", "-depth", "5", "-concurrency", "20", "-silent", "-no-color", "-ef", "css,png,jpg,jpeg,gif,ico,svg,ttf,woff,woff2,eot,pdf,mp4,mp3,zip"}
	if core.GlobalConfig.Insecure {
		args = append(args, "-insecure")
	}
	return runCmdLines(ctx, "katana", args...)
}

func RunWaybackurls(host string) []string {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	bare := core.BareDomain(host)
	return runCmdLines(ctx, "waybackurls", bare)
}

func RunHakrawler(url string) []string {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	args := []string{"-url", url, "-depth", "3", "-js", "-plain"}
	if core.GlobalConfig.Insecure {
		args = append(args, "-insecure")
	}
	return runCmdLines(ctx, "hakrawler", args...)
}

func RunSubjs(urlStr string) []string {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "subjs")
	cmd.Stdin = strings.NewReader(urlStr + "\n")
	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	_ = cmd.Run()
	var res []string
	for _, l := range strings.Split(stdout.String(), "\n") {
		l = strings.TrimSpace(l)
		if strings.HasPrefix(l, "http") {
			res = append(res, l)
		}
	}
	return res
}

func RunCariddi(urlStr string) ([]string, []core.Finding) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	cmd := exec.CommandContext(ctx, "cariddi", "-s", "-e", "-plain")
	cmd.Stdin = strings.NewReader(urlStr + "\n")
	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	_ = cmd.Run()

	var urls []string
	var findings []core.Finding

	for _, line := range strings.Split(stdout.String(), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		if strings.HasPrefix(line, "[SECRET]") {
			secretPart := strings.TrimSpace(line[len("[SECRET]"):])
			if len(secretPart) > 8 {
				findings = append(findings, core.Finding{
					Tool:    "cariddi",
					Type:    "auto",
					URL:     urlStr,
					Match:   secretPart,
					Entropy: fmt.Sprintf("%.2f", core.ShannonEntropy(secretPart)),
				})
			}
		} else if strings.HasPrefix(line, "http") {
			urls = append(urls, line)
		}
	}
	return urls, findings
}
