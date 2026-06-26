package collector

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"siphon-go/core"
	"strings"
	"time"
)

func runCmdLinesStdin(ctx context.Context, input []string, name string, args ...string) []string {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = append(os.Environ(), "NO_COLOR=1")
	cmd.Stdin = strings.NewReader(strings.Join(input, "\n") + "\n")
	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	_ = cmd.Run()
	var res []string
	for _, l := range strings.Split(stdout.String(), "\n") {
		l = strings.TrimSpace(l)
		if strings.Contains(l, "http") {
			idx := strings.Index(l, "http")
			res = append(res, l[idx:])
		}
	}
	return res
}

func RunGau(hosts []string) []string {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	var bareHosts []string
	for _, h := range hosts {
		bareHosts = append(bareHosts, core.BareDomain(h))
	}
	return runCmdLinesStdin(ctx, bareHosts, "gau", "--providers", "wayback,commoncrawl,otx,urlscan", "--threads", "20", "--blacklist", "ttf,woff,woff2,eot,svg,png,jpg,jpeg,gif,ico,css,pdf,mp4,mp3,zip")
}

func RunKatana(urls []string) []string {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	// Removed -kf all and -aff to significantly improve speed. Reduced depth to 3.
	args := []string{"-jc", "-d", "3", "-c", "50", "-silent", "-nc", "-ef", "css,png,jpg,jpeg,gif,ico,svg,ttf,woff,woff2,eot,pdf,mp4,mp3,zip"}
	if core.GlobalConfig.Insecure {
		args = append(args, "-insecure")
	}
	return runCmdLinesStdin(ctx, urls, "katana", args...)
}

func RunWaybackurls(hosts []string) []string {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	var bareHosts []string
	for _, h := range hosts {
		bareHosts = append(bareHosts, core.BareDomain(h))
	}
	return runCmdLinesStdin(ctx, bareHosts, "waybackurls")
}

func RunHakrawler(urls []string) []string {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	// Changed invalid flags -depth, -js, -plain to standard -d
	args := []string{"-d", "3"}
	if core.GlobalConfig.Insecure {
		args = append(args, "-insecure")
	}
	return runCmdLinesStdin(ctx, urls, "hakrawler", args...)
}

func RunSubjs(urls []string) []string {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	return runCmdLinesStdin(ctx, urls, "subjs")
}

func RunCariddi(urls []string) ([]string, []core.Finding) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	cmd := exec.CommandContext(ctx, "cariddi", "-s", "-e", "-plain")
	cmd.Env = append(os.Environ(), "NO_COLOR=1")
	cmd.Stdin = strings.NewReader(strings.Join(urls, "\n") + "\n")
	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	_ = cmd.Run()

	var outUrls []string
	var findings []core.Finding

	for _, line := range strings.Split(stdout.String(), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		if strings.Contains(line, "[SECRET]") {
			idx := strings.Index(line, "[SECRET]")
			secretPart := strings.TrimSpace(line[idx+len("[SECRET]"):])
			if len(secretPart) > 8 {
				findings = append(findings, core.Finding{
					Tool:    "cariddi",
					Type:    "auto",
					URL:     "cariddi-batch", // Note: Cariddi doesn't output the source URL in plain mode easily, but we can keep it as batch
					Match:   secretPart,
					Entropy: fmt.Sprintf("%.2f", core.ShannonEntropy(secretPart)),
				})
			}
		} else if strings.Contains(line, "http") {
			idx := strings.Index(line, "http")
			outUrls = append(outUrls, line[idx:])
		}
	}
	return outUrls, findings
}
