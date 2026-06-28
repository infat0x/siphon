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

// ── Color Palette ────────────────────────────────────────────────────────
// Monochrome palette: white for emphasis, gray for structure, dim for noise.
const (
	cWhite = "\033[97m"     // bright white — emphasis
	cGray  = "\033[38;5;245m" // mid gray — labels
	cDim   = "\033[38;5;240m" // dark gray — structure lines
	cGreen = "\033[38;5;35m"  // muted green — success
	cRed   = "\033[38;5;160m" // muted red — errors
	cAmber = "\033[38;5;214m" // amber — warnings
)

// MultiPrinter removed

// ClearScreen clears the terminal for a clean start.
func ClearScreen() {
	if runtime.GOOS == "windows" {
		cmd := exec.Command("cmd", "/c", "cls")
		cmd.Stdout = os.Stdout
		cmd.Run()
	} else {
		fmt.Print("\033[H\033[2J")
	}
}

// PrintBanner prints a minimal one-line branded header.
func PrintBanner() {
	ClearScreen()
	fmt.Println()
	fmt.Printf("  %s%ssiphon%s %sv7%s %s|%s js secret scanner %s|%s 15 engines%s\n",
		cWhite, BOLD, RESET,
		cGray, RESET,
		cDim, RESET,
		cDim, RESET,
		RESET)
	PrintDivider()
}

// PrintSection prints a step header: [1/5] title
func PrintSection(step int, total int, title string) {
	fmt.Println()
	fmt.Println()
	fmt.Printf("  %s[%d/%d]%s %s%s%s\n",
		cGray, step, total, RESET,
		cWhite, title, RESET)
}

// PrintResult prints a key-value line:  > label    value
func PrintResult(icon string, label string, value interface{}, valueColor string) {
	if valueColor == "" {
		valueColor = cWhite
	}
	// icon is ignored in the new UI — we use ">" prefix
	fmt.Printf("  %s>%s %-16s %s%s%v%s\n",
		cDim, RESET,
		label,
		valueColor, BOLD, value, RESET)
}

// PrintSuccess prints a completion message.
func PrintSuccess(msg string) {
	fmt.Printf("  %s%s[OK]%s %s\n", cGreen, BOLD, RESET, msg)
}

// PrintWarning prints a warning message.
func PrintWarning(msg string) {
	fmt.Printf("  %s%s[WARN]%s %s\n", cAmber, BOLD, RESET, msg)
}

// PrintError prints an error message.
func PrintError(msg string) {
	fmt.Printf("  %s%s[ERR]%s %s\n", cRed, BOLD, RESET, msg)
}

// PrintDivider prints a subtle horizontal rule.
func PrintDivider() {
	fmt.Printf("  %s%s%s\n", cDim, strings.Repeat("\u2500", 52), RESET)
}

// PrintScanEngineStart prints a compact scan phase header.
func PrintScanEngineStart(engineCount int) {
	fmt.Println()
	PrintDivider()
	fmt.Printf("  %s%s%d scan engines starting%s\n", cWhite, BOLD, engineCount, RESET)
	PrintDivider()
}

// PrintFinalStats prints the final statistics block.
func PrintFinalStats(findings int, critical int, high int, medium int, elapsed time.Duration, reportPath string) {
	fmt.Println()
	PrintDivider()
	fmt.Printf("  %s%sscan complete%s\n", cWhite, BOLD, RESET)
	PrintDivider()

	fmt.Printf("  %stotal%s       %s%s%d%s\n", cGray, RESET, cWhite, BOLD, findings, RESET)
	if critical > 0 {
		fmt.Printf("  %scritical%s    %s%s%d%s\n", cGray, RESET, cRed, BOLD, critical, RESET)
	}
	if high > 0 {
		fmt.Printf("  %shigh%s        %s%s%d%s\n", cGray, RESET, cAmber, BOLD, high, RESET)
	}
	if medium > 0 {
		fmt.Printf("  %smedium%s      %s%s%d%s\n", cGray, RESET, cWhite, BOLD, medium, RESET)
	}
	fmt.Printf("  %sduration%s    %s%s\n", cGray, RESET, elapsed.Round(time.Second).String(), RESET)
	fmt.Printf("  %sreport%s      %s%s\n", cGray, RESET, reportPath, RESET)

	PrintDivider()
	fmt.Println()
}

// ── pterm setup ─────────────────────────────────────────────────────────

func InitUI() {
	// Spinner — minimal dots, no emoji
	pterm.DefaultSpinner.Sequence = []string{". ", ".. ", "...", ".. ", ". ", "   "}
	pterm.DefaultSpinner.Style = pterm.NewStyle(pterm.FgWhite)
	pterm.DefaultSpinner.SuccessPrinter = &pterm.PrefixPrinter{
		MessageStyle: pterm.NewStyle(pterm.FgWhite),
		Prefix:       pterm.Prefix{Text: " [OK] ", Style: pterm.NewStyle(pterm.FgGreen, pterm.Bold)},
	}
	pterm.DefaultSpinner.FailPrinter = &pterm.PrefixPrinter{
		MessageStyle: pterm.NewStyle(pterm.FgWhite),
		Prefix:       pterm.Prefix{Text: " [FAIL] ", Style: pterm.NewStyle(pterm.FgRed, pterm.Bold)},
	}

	// Prefix printers — clean text markers
	pterm.Info.Prefix = pterm.Prefix{Text: "  [i] ", Style: pterm.NewStyle(pterm.FgWhite)}
	pterm.Success.Prefix = pterm.Prefix{Text: "  [OK] ", Style: pterm.NewStyle(pterm.FgGreen, pterm.Bold)}
	pterm.Error.Prefix = pterm.Prefix{Text: "  [ERR] ", Style: pterm.NewStyle(pterm.FgRed, pterm.Bold)}
	pterm.Warning.Prefix = pterm.Prefix{Text: "  [WARN] ", Style: pterm.NewStyle(pterm.FgYellow)}

	// Progress bar — minimal, monochrome
	pterm.ThemeDefault.ProgressbarTitleStyle = *pterm.NewStyle(pterm.FgWhite)
	pterm.ThemeDefault.ProgressbarBarStyle = *pterm.NewStyle(pterm.FgWhite)

	pterm.DefaultProgressbar.BarCharacter = "#"
	pterm.DefaultProgressbar.LastCharacter = "#"
	pterm.DefaultProgressbar.BarFiller = "-"
	pterm.DefaultProgressbar.ShowPercentage = true
	pterm.DefaultProgressbar.ShowCount = true
	pterm.DefaultProgressbar.ShowElapsedTime = true
	pterm.DefaultProgressbar.BarStyle = pterm.NewStyle(pterm.FgWhite)
	pterm.DefaultProgressbar.TitleStyle = pterm.NewStyle(pterm.FgWhite, pterm.Bold)
}

func StopUI() {
	// No longer needed
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

type DummySpinner struct{}

func (d *DummySpinner) Success(msg string) {
	PrintSuccess(msg)
}

func (d *DummySpinner) Fail(msg string) {
	PrintError(msg)
}

func StartSpinner(text string) *DummySpinner {
	fmt.Printf("  %s>%s %s\n", cDim, RESET, text)
	return &DummySpinner{}
}

func StartProgressBar(total int, text string) *pterm.ProgressbarPrinter {
	p, _ := pterm.DefaultProgressbar.WithTotal(total).WithTitle("  " + text).Start()
	return p
}
