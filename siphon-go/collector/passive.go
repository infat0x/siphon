package collector

import (
	"bytes"
	"context"
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
