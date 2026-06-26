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
			u := l[idx:]
			if escapeIdx := strings.Index(u, "\x1b"); escapeIdx != -1 {
				u = u[:escapeIdx]
			}
			if spaceIdx := strings.Index(u, " "); spaceIdx != -1 {
				u = u[:spaceIdx]
			}
			u = strings.TrimSpace(u)
			res = append(res, u)
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
}
