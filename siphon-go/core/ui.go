package core

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/pterm/pterm"
)

var Multi *pterm.MultiPrinter

// ClearScreen clears the terminal for a clean start
func ClearScreen() {
	if runtime.GOOS == "windows" {
		cmd := exec.Command("cmd", "/c", "cls")
		cmd.Stdout = os.Stdout
		cmd.Run()
	} else {
		fmt.Print("\033[H\033[2J")
	}
}

// PrintBanner prints a sleek, minimal branded header
func PrintBanner() {
	ClearScreen()

	// Top gradient line
	gradientLine := ""
	colors := []string{"\033[38;5;39m", "\033[38;5;38m", "\033[38;5;37m", "\033[38;5;36m", "\033[38;5;35m", "\033[38;5;34m"}
	blockChar := "━"
	for i := 0; i < 60; i++ {
		gradientLine += colors[i%len(colors)] + blockChar
	}
	fmt.Println(gradientLine + RESET)
	fmt.Println()

	// Brand name with gradient coloring
	s := "S I P H O N"
	brandColors := []string{
		"\033[38;5;51m", // bright cyan
		"\033[38;5;45m",
		"\033[38;5;39m", // blue
		"\033[38;5;33m",
		"\033[38;5;27m",
		"\033[38;5;21m", // deep blue
		"\033[38;5;57m", // purple
		"\033[38;5;93m",
		"\033[38;5;129m",
		"\033[38;5;165m", // magenta
		"\033[38;5;201m",
	}
	brand := "    "
	chars := strings.Split(s, "")
	for i, c := range chars {
		brand += brandColors[i%len(brandColors)] + BOLD + c
	}
	fmt.Println(brand + RESET)

	// Subtitle
	fmt.Printf("    %s%sv7 Ultra  │  14 Scan Engines  │  Secret Hunter%s\n", DIM, "\033[38;5;245m", RESET)
	fmt.Println()

	// Bottom gradient line
	fmt.Println(gradientLine + RESET)
	fmt.Println()
}

// PrintSection prints a styled section header
func PrintSection(step int, total int, title string) {
	stepColor := "\033[38;5;39m"  // blue
	titleColor := "\033[38;5;255m" // white
	dimColor := "\033[38;5;240m"

	fmt.Printf("  %s%s[%d/%d]%s %s%s%s%s\n",
		stepColor, BOLD, step, total, RESET,
		titleColor, BOLD, title, RESET)

	// thin underline
	lineLen := len(title) + 8
	line := strings.Repeat("─", lineLen)
	fmt.Printf("  %s%s%s\n", dimColor, line, RESET)
}

// PrintResult prints a result line with icon
func PrintResult(icon string, label string, value interface{}, valueColor string) {
	if valueColor == "" {
		valueColor = "\033[38;5;48m" // green
	}
	fmt.Printf("  %s  %-20s %s%s%v%s\n",
		icon, label, valueColor, BOLD, value, RESET)
}

// PrintSuccess prints a success completion message
func PrintSuccess(msg string) {
	fmt.Printf("  %s✓%s  %s\n", "\033[38;5;48m", RESET, msg)
}

// PrintWarning prints a warning message
func PrintWarning(msg string) {
	fmt.Printf("  %s⚠%s  %s\n", "\033[38;5;220m", RESET, msg)
}

// PrintError prints an error message
func PrintError(msg string) {
	fmt.Printf("  %s✗%s  %s\n", "\033[38;5;196m", RESET, msg)
}

// PrintDivider prints a subtle divider
func PrintDivider() {
	fmt.Printf("  %s%s%s\n", "\033[38;5;236m", strings.Repeat("─", 56), RESET)
}

// PrintScanEngineStart prints the scan engine launch header
func PrintScanEngineStart(engineCount int) {
	fmt.Println()
	boxTop := "\033[38;5;39m" + "  ┌" + strings.Repeat("─", 52) + "┐" + RESET
	boxMid := fmt.Sprintf("  │%s  ⚡ Launching %d Scan Engines...                    %s│", "\033[38;5;255m"+BOLD, engineCount, RESET+"\033[38;5;39m")
	boxBot := "\033[38;5;39m" + "  └" + strings.Repeat("─", 52) + "┘" + RESET
	fmt.Println(boxTop)
	fmt.Println(boxMid)
	fmt.Println(boxBot)
	fmt.Println()
}

// PrintFinalStats prints the final statistics box
func PrintFinalStats(findings int, critical int, high int, medium int, elapsed time.Duration) {
	fmt.Println()
	bc := "\033[38;5;39m"
	fmt.Println(bc + "  ┌" + strings.Repeat("─", 52) + "┐" + RESET)
	fmt.Printf("  │%s  %-50s%s│\n", "\033[38;5;255m"+BOLD, "SCAN COMPLETE", RESET+bc)
	fmt.Println(bc + "  ├" + strings.Repeat("─", 52) + "┤" + RESET)

	fmt.Printf("  │  %-18s %s%-30d%s  │\n", "Total Findings:", "\033[38;5;255m"+BOLD, findings, RESET+bc)
	if critical > 0 {
		fmt.Printf("  │  %-18s %s%-30d%s  │\n", "🔴 CRITICAL:", "\033[38;5;196m"+BOLD, critical, RESET+bc)
	}
	if high > 0 {
		fmt.Printf("  │  %-18s %s%-30d%s  │\n", "🟠 HIGH:", "\033[38;5;208m"+BOLD, high, RESET+bc)
	}
	if medium > 0 {
		fmt.Printf("  │  %-18s %s%-30d%s  │\n", "🟡 MEDIUM:", "\033[38;5;220m"+BOLD, medium, RESET+bc)
	}
	fmt.Printf("  │  %-18s %s%-30s%s  │\n", "Duration:", "\033[38;5;245m", elapsed.Round(time.Second).String(), RESET+bc)

	fmt.Println(bc + "  └" + strings.Repeat("─", 52) + "┘" + RESET)
	fmt.Println()
}

func InitUI() {
	// Sleek spinner
	pterm.DefaultSpinner.Sequence = []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}
	pterm.DefaultSpinner.Style = pterm.NewStyle(pterm.FgCyan)
	pterm.DefaultSpinner.SuccessPrinter = &pterm.PrefixPrinter{
		MessageStyle: pterm.NewStyle(pterm.FgGreen),
		Prefix:       pterm.Prefix{Text: " ✓ ", Style: pterm.NewStyle(pterm.FgGreen, pterm.Bold)},
	}
	pterm.DefaultSpinner.FailPrinter = &pterm.PrefixPrinter{
		MessageStyle: pterm.NewStyle(pterm.FgRed),
		Prefix:       pterm.Prefix{Text: " ✗ ", Style: pterm.NewStyle(pterm.FgRed, pterm.Bold)},
	}

	// Clean prefixes
	pterm.Info.Prefix = pterm.Prefix{Text: "  ℹ ", Style: pterm.NewStyle(pterm.FgCyan)}
	pterm.Success.Prefix = pterm.Prefix{Text: "  ✓ ", Style: pterm.NewStyle(pterm.FgGreen, pterm.Bold)}
	pterm.Error.Prefix = pterm.Prefix{Text: "  ✗ ", Style: pterm.NewStyle(pterm.FgRed, pterm.Bold)}
	pterm.Warning.Prefix = pterm.Prefix{Text: "  ⚠ ", Style: pterm.NewStyle(pterm.FgYellow)}

	// Progress bar — sleek minimal style
	pterm.ThemeDefault.ProgressbarTitleStyle = *pterm.NewStyle(pterm.FgLightCyan)
	pterm.ThemeDefault.ProgressbarBarStyle = *pterm.NewStyle(pterm.FgCyan)

	pterm.DefaultProgressbar.BarCharacter = "█"
	pterm.DefaultProgressbar.LastCharacter = "█"
	pterm.DefaultProgressbar.BarFiller = "░"
	pterm.DefaultProgressbar.ShowPercentage = true
	pterm.DefaultProgressbar.ShowCount = true
	pterm.DefaultProgressbar.ShowElapsedTime = true
	pterm.DefaultProgressbar.BarStyle = pterm.NewStyle(pterm.FgCyan)
	pterm.DefaultProgressbar.TitleStyle = pterm.NewStyle(pterm.FgWhite, pterm.Bold)

	Multi, _ = pterm.DefaultMultiPrinter.Start()
}

func StopUI() {
	Multi.Stop()
}

func Logf(format string, a ...interface{}) {
	msg := fmt.Sprintf(format, a...)
	fmt.Print(msg)
	Info(msg)
}

func Logln(a ...interface{}) {
	msg := fmt.Sprintln(a...)
	fmt.Print(msg)
	Info(msg)
}

func StartSpinner(text string) *pterm.SpinnerPrinter {
	s, _ := pterm.DefaultSpinner.WithWriter(Multi.NewWriter()).WithText(text).Start()
	return s
}

func StartProgressBar(total int, text string) *pterm.ProgressbarPrinter {
	p, _ := pterm.DefaultProgressbar.WithTotal(total).WithTitle(text).WithWriter(Multi.NewWriter()).Start()
	return p
}
