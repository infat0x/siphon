# Terminal UI (`core/ui.go`)

The `ui.go` module leverages the `pterm` library to provide Siphon with its signature minimal, monochrome terminal interface.

## Overview

Siphon's aesthetic is designed to be sleek and professional, avoiding the messy, multi-colored output typical of many hacking tools. It relies on bright white for emphasis, gray for structure, and muted colors for states (green for success, red for errors).

> [!NOTE]
> The entire UI is configured to override default `pterm` behaviors, silencing emojis and loud progress bars in favor of a clean, hacker-centric look.

## Color Palette

The module begins by defining raw ANSI escape codes for terminal formatting.

```go
const (
	cWhite = "\033[97m"       // bright white — emphasis
	cGray  = "\033[38;5;245m" // mid gray — labels
	cDim   = "\033[38;5;240m" // dark gray — structure lines
	cGreen = "\033[38;5;35m"  // muted green — success
	cRed   = "\033[38;5;160m" // muted red — errors
	cAmber = "\033[38;5;214m" // amber — warnings
)
```

## Pterm Customization

The `InitUI()` function completely re-themes the `pterm` primitives. For instance, the default spinner is replaced with a simple sequence of dots.

```go
func InitUI() {
	// Spinner — minimal dots, no emoji
	pterm.DefaultSpinner.Sequence = []string{". ", ".. ", "...", ".. ", ". ", "   "}
	pterm.DefaultSpinner.Style = pterm.NewStyle(pterm.FgWhite)
	
	// Progress bar — minimal, monochrome
	pterm.DefaultProgressbar.BarCharacter = "#"
	pterm.DefaultProgressbar.LastCharacter = "#"
	pterm.DefaultProgressbar.BarFiller = "-"
	pterm.DefaultProgressbar.BarStyle = pterm.NewStyle(pterm.FgWhite)
}
```

> [!TIP]
> By centralizing all UI functions (like `PrintSuccess`, `PrintWarning`, and `StartProgressBar`) in this file, Siphon guarantees a consistent visual hierarchy across all modules. If you want to change the visual theme of Siphon, you only need to edit `ui.go`.
