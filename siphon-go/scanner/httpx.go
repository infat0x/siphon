package scanner

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"siphon-go/core"
	"strings"
	"time"
)

func RunHttpx(subsFile string, liveFile string) []string {
	fmt.Printf("%s\n", core.DIM+strings.Repeat("━", 60)+core.RESET)
	fmt.Printf("  %s[1/5]  Live Host Detection  →  httpx%s\n", core.BOLD, core.RESET)
	if core.GlobalConfig.Insecure {
		fmt.Printf("         %s⚠  TLS verification disabled (--insecure)%s\n", core.YELLOW, core.RESET)
	}
	fmt.Printf("%s\n", core.DIM+strings.Repeat("━", 60)+core.RESET)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	args := []string{
		"-l", subsFile,
		"-threads", fmt.Sprintf("%d", core.GlobalConfig.Threads),
		"-silent",
		"-no-color",
		"-o", liveFile,
		"-timeout", "10",
		"-retries", "2",
		"-follow-redirects",
		"-status-code",
		"-title",
		"-tech-detect",
		"-web-server",
	}
	if core.GlobalConfig.Insecure {
		args = append(args, "-no-verify-ssl")
	}

	cmd := exec.CommandContext(ctx, "httpx", args...)
	_ = cmd.Run()

	var live []string
	data, err := os.ReadFile(liveFile)
	if err == nil {
		lines := strings.Split(string(data), "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			parts := strings.Split(line, " ")
			url := parts[0]
			if strings.HasPrefix(url, "http") {
				live = append(live, url)
			}
		}
		live = core.Dedup(live)
		os.WriteFile(liveFile, []byte(strings.Join(live, "\n")+"\n"), 0644)
	}

	fmt.Printf("  %s✔%s  %s%d%s live hosts  →  %s%s%s\n", core.GREEN, core.RESET, core.BOLD, len(live), core.RESET, core.DIM, liveFile, core.RESET)
	return live
}
