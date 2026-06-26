package core

import (
	"fmt"
	"github.com/pterm/pterm"
)

var Multi *pterm.MultiPrinter

func InitUI() {
	// Disable pterm's prefix on info to match our custom style
	pterm.Info.Prefix = pterm.Prefix{Text: " INFO ", Style: pterm.NewStyle(pterm.BgMagenta, pterm.FgBlack)}
	pterm.Success.Prefix = pterm.Prefix{Text: " OK ", Style: pterm.NewStyle(pterm.BgGreen, pterm.FgBlack)}
	pterm.Error.Prefix = pterm.Prefix{Text: " ERR ", Style: pterm.NewStyle(pterm.BgRed, pterm.FgBlack)}
	pterm.Warning.Prefix = pterm.Prefix{Text: " WARN ", Style: pterm.NewStyle(pterm.BgYellow, pterm.FgBlack)}

	// Qlobal rənglərin tənzimlənməsi
	pterm.ThemeDefault.SpinnerStyle = *pterm.NewStyle(pterm.FgGreen)
	pterm.ThemeDefault.ProgressbarTitleStyle = *pterm.NewStyle(pterm.FgMagenta, pterm.Bold)
	pterm.ThemeDefault.ProgressbarBarStyle = *pterm.NewStyle(pterm.FgGreen)

	// Progress bar formatının tənzimlənməsi (shades_classic tərzi)
	pterm.DefaultProgressbar.BarCharacter = "█"
	pterm.DefaultProgressbar.LastCharacter = "█"
	pterm.DefaultProgressbar.BarFiller = "░"
	pterm.DefaultProgressbar.ShowPercentage = true
	pterm.DefaultProgressbar.ShowCount = true
	pterm.DefaultProgressbar.ShowElapsedTime = true

	Multi, _ = pterm.DefaultMultiPrinter.Start()
}

func StopUI() {
	Multi.Stop()
}

func Logf(format string, a ...interface{}) {
	msg := fmt.Sprintf(format, a...)
	pterm.Info.Print(msg)
	Info(msg)
}

func Logln(a ...interface{}) {
	msg := fmt.Sprintln(a...)
	pterm.Info.Print(msg)
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
