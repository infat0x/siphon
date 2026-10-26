package core

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
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
	if GlobalConfig.Silent {
		return
	}
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
	if GlobalConfig.Silent {
		return
	}
	fmt.Println()
	fmt.Println()
	fmt.Printf("  %s[%d/%d]%s %s%s%s\n",
		cGray, step, total, RESET,
		cWhite, title, RESET)
}

// PrintResult prints a key-value line:  > label    value
func PrintResult(icon string, label string, value interface{}, valueColor string) {
	if GlobalConfig.Silent {
		return
	}
	if valueColor == "" {
		valueColor = cWhite
	}
	// icon is ignored in the new UI — we use ">" prefix
	fmt.Printf("  %s>%s %-16s %s%s%v%s\n",
		cDim, RESET,
		label,
		valueColor, BOLD, value, RESET)
}

// PrintAuthStatus probes targetURL and prints AUTH (green) or UNAUTH (red).
func PrintAuthStatus(targetURL string) {
	if GlobalConfig.Silent {
		return
	}
	isAuth, statusText := CheckAuthStatus(targetURL)
	if isAuth {
		PrintResult("", "auth", statusText, GREEN)
	} else {
		PrintResult("", "auth", statusText, RED)
	}
}

// PrintSuccess prints a completion message.
func PrintSuccess(msg string) {
	if GlobalConfig.Silent {
		return
	}
	fmt.Printf("  %s%s[OK]%s %s\n", cGreen, BOLD, RESET, msg)
}

// PrintWarning prints a warning message.
func PrintWarning(msg string) {
	if GlobalConfig.Silent {
		return
	}
	fmt.Printf("  %s%s[WARN]%s %s\n", cAmber, BOLD, RESET, msg)
}

// PrintError prints an error message.
func PrintError(msg string) {
	fmt.Printf("  %s%s[ERR]%s %s\n", cRed, BOLD, RESET, msg)
}

// PrintDivider prints a subtle horizontal rule.
func PrintDivider() {
	if GlobalConfig.Silent {
		return
	}
	fmt.Printf("  %s%s%s\n", cDim, strings.Repeat("\u2500", 52), RESET)
}

// PrintScanEngineStart prints a compact scan phase header.
func PrintScanEngineStart(engineCount int) {
	if GlobalConfig.Silent {
		return
	}
	fmt.Println()
	PrintDivider()
	fmt.Printf("  %s%s%d scan engines starting%s\n", cWhite, BOLD, engineCount, RESET)
	PrintDivider()
}

// PrintFinalStats prints the final statistics block.
func PrintFinalStats(findings int, critical int, high int, medium int, elapsed time.Duration, reportPath string) {
	if GlobalConfig.Silent {
		return
	}
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
	if !GlobalConfig.Silent {
		fmt.Print(msg)
	}
	Info(msg)
}

func Logln(a ...interface{}) {
	msg := fmt.Sprintln(a...)
	if !GlobalConfig.Silent {
		fmt.Print(msg)
	}
	Info(msg)
}

type Spinner struct {
	ptermSpinner *pterm.SpinnerPrinter
}

func (s *Spinner) Success(msg string) {
	if s == nil {
		return
	}
	if s.ptermSpinner != nil {
		s.ptermSpinner.Success(msg)
	} else if !GlobalConfig.Silent {
		PrintSuccess(msg)
	}
}

func (s *Spinner) Fail(msg string) {
	if s == nil {
		return
	}
	if s.ptermSpinner != nil {
		s.ptermSpinner.Fail(msg)
	} else if !GlobalConfig.Silent {
		PrintError(msg)
	}
}

func (s *Spinner) UpdateText(text string) {
	if s != nil && s.ptermSpinner != nil {
		s.ptermSpinner.UpdateText(text)
	}
}

func StartSpinner(text string) *Spinner {
	if GlobalConfig.Silent {
		return &Spinner{}
	}
	sp, err := pterm.DefaultSpinner.Start(text)
	if err != nil {
		fmt.Printf("  %s>%s %s\n", cDim, RESET, text)
		return &Spinner{}
	}
	return &Spinner{ptermSpinner: sp}
}

// ParallelTracker coordinates a single dynamic progress bar across multiple concurrent goroutines.
type ParallelTracker struct {
	mu          sync.Mutex
	pb          *pterm.ProgressbarPrinter
	total       int
	completed   int
	baseTitle   string
	itemLabel   string
	totalItems  int
	activeTasks map[string]struct{}
	results     map[string]int
}

func NewParallelTracker(total int, baseTitle string, itemLabel string) *ParallelTracker {
	tracker := &ParallelTracker{
		total:       total,
		baseTitle:   baseTitle,
		itemLabel:   itemLabel,
		activeTasks: make(map[string]struct{}),
		results:     make(map[string]int),
	}

	if !GlobalConfig.Silent {
		pb, err := pterm.DefaultProgressbar.WithTotal(total).WithTitle("  " + baseTitle).Start()
		if err == nil {
			tracker.pb = pb
		}
	}
	return tracker
}

func (t *ParallelTracker) TaskStarted(name string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.activeTasks[name] = struct{}{}
	t.updateTitleLocked()
}

func (t *ParallelTracker) TaskFinished(name string, itemsCount int) {
	t.mu.Lock()
	defer t.mu.Unlock()

	delete(t.activeTasks, name)
	t.completed++
	t.totalItems += itemsCount
	t.results[name] = itemsCount

	if t.pb != nil {
		t.pb.Increment()
	}
	t.updateTitleLocked()
}

func (t *ParallelTracker) updateTitleLocked() {
	if t.pb == nil {
		return
	}

	var activeList []string
	for name := range t.activeTasks {
		activeList = append(activeList, name)
		if len(activeList) >= 2 {
			break
		}
	}

	title := fmt.Sprintf("  %s", t.baseTitle)
	if len(activeList) > 0 {
		title += fmt.Sprintf(" (%s", strings.Join(activeList, ", "))
		if len(t.activeTasks) > len(activeList) {
			title += fmt.Sprintf(" +%d", len(t.activeTasks)-len(activeList))
		}
		title += ")"
	}
	if t.totalItems > 0 {
		title += fmt.Sprintf(" | %d %s", t.totalItems, t.itemLabel)
	}

	t.pb.UpdateTitle(title)
}

func (t *ParallelTracker) Stop(doneMsg string) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.pb != nil {
		t.pb.Stop()
	}

	if doneMsg != "" {
		PrintSuccess(doneMsg)
	}
}

func (t *ParallelTracker) Results() map[string]int {
	t.mu.Lock()
	defer t.mu.Unlock()
	cp := make(map[string]int, len(t.results))
	for k, v := range t.results {
		cp[k] = v
	}
	return cp
}

func StartProgressBar(total int, text string) *pterm.ProgressbarPrinter {
	if GlobalConfig.Silent {
		return nil
	}
	p, _ := pterm.DefaultProgressbar.WithTotal(total).WithTitle("  " + text).Start()
	return p
}
