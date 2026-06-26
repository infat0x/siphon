package core

import (
	"fmt"
	"strings"
	"sync"
	"time"
)

type StageStatus int

const (
	StagePending StageStatus = iota
	StageRunning
	StageDone
	StageSkipped
	StageError
)

type UIStage struct {
	Name     string
	Status   StageStatus
	Progress int
	Total    int
	Message  string
	Start    time.Time
	Elapsed  time.Duration
}

type StatusUI struct {
	mu     sync.Mutex
	stages []*UIStage
	ticker *time.Ticker
	stop   chan struct{}
	active bool
}

var UI *StatusUI

func InitUI() {
	UI = &StatusUI{
		stages: []*UIStage{
			{Name: "1. Live Host Detection", Status: StagePending},
			{Name: "2. URL Collection", Status: StagePending},
			{Name: "3. JS Extraction", Status: StagePending},
			{Name: "4. Downloading JS", Status: StagePending},
			{Name: "5. Secret Scanning", Status: StagePending},
		},
		stop: make(chan struct{}),
	}
}

func (u *StatusUI) Start() {
	u.active = true
	lines := len(u.stages) + 2
	for i := 0; i < lines; i++ {
		fmt.Println()
	}
	
	u.ticker = time.NewTicker(200 * time.Millisecond)
	go func() {
		for {
			select {
			case <-u.ticker.C:
				u.render()
			case <-u.stop:
				u.render()
				return
			}
		}
	}()
}

func (u *StatusUI) Stop() {
	if u.active {
		u.ticker.Stop()
		close(u.stop)
		u.active = false
		fmt.Println()
	}
}

func (u *StatusUI) UpdateStage(idx int, status StageStatus, msg string) {
	u.mu.Lock()
	defer u.mu.Unlock()
	if idx >= 0 && idx < len(u.stages) {
		s := u.stages[idx]
		s.Status = status
		if msg != "" {
			s.Message = msg
		}
		if status == StageRunning && s.Start.IsZero() {
			s.Start = time.Now()
		}
		if (status == StageDone || status == StageSkipped || status == StageError) && !s.Start.IsZero() && s.Elapsed == 0 {
			s.Elapsed = time.Since(s.Start)
		}
	}
}

func (u *StatusUI) UpdateProgress(idx int, prog, total int) {
	u.mu.Lock()
	defer u.mu.Unlock()
	if idx >= 0 && idx < len(u.stages) {
		u.stages[idx].Progress = prog
		u.stages[idx].Total = total
	}
}

func (u *StatusUI) Log(msg string) {
	u.mu.Lock()
	defer u.mu.Unlock()
	
	if !u.active {
		fmt.Print(msg)
		return
	}
	
	linesToClear := len(u.stages) + 2
	fmt.Printf("\033[%dA\033[0J", linesToClear)
	
	fmt.Print(msg)
	if !strings.HasSuffix(msg, "\n") {
		fmt.Println()
	}
	
	for i := 0; i < linesToClear; i++ {
		fmt.Println()
	}
}

func Logf(format string, a ...interface{}) {
	if UI != nil {
		UI.Log(fmt.Sprintf(format, a...))
	} else {
		fmt.Printf(format, a...)
	}
}

func Logln(a ...interface{}) {
	if UI != nil {
		UI.Log(fmt.Sprintln(a...))
	} else {
		fmt.Println(a...)
	}
}

func (u *StatusUI) render() {
	u.mu.Lock()
	defer u.mu.Unlock()
	
	if !u.active {
		return
	}

	lines := len(u.stages) + 2
	out := fmt.Sprintf("\033[%dA\r", lines)
	out += fmt.Sprintf("%s\n", DIM+strings.Repeat("━", 60)+RESET)
	
	for _, s := range u.stages {
		icon := " "
		color := RESET
		switch s.Status {
		case StagePending:
			icon = "○"
			color = DIM
		case StageRunning:
			icon = "●"
			color = CYAN
		case StageDone:
			icon = "✔"
			color = GREEN
		case StageSkipped:
			icon = "⏭"
			color = YELLOW
		case StageError:
			icon = "✖"
			color = RED
		}
		
		elapsedStr := ""
		if !s.Start.IsZero() {
			if s.Elapsed > 0 {
				elapsedStr = fmt.Sprintf(" [%s]", s.Elapsed.Round(time.Second))
			} else {
				elapsedStr = fmt.Sprintf(" [%s]", time.Since(s.Start).Round(time.Second))
			}
		}

		progStr := ""
		if s.Total > 0 {
			percent := float64(s.Progress) / float64(s.Total) * 100.0
			etaStr := ""
			if s.Progress > 0 && s.Progress < s.Total && s.Status == StageRunning {
				elapsedSecs := time.Since(s.Start).Seconds()
				totalEst := elapsedSecs / (float64(s.Progress) / float64(s.Total))
				left := totalEst - elapsedSecs
				if left < 0 { left = 0 }
				
				if left > 60 {
					etaStr = fmt.Sprintf(" • %.0fm left", left/60.0)
				} else {
					etaStr = fmt.Sprintf(" • %.0fs left", left)
				}
			}
			
			barLen := 15
			filled := int(float64(barLen) * (float64(s.Progress) / float64(s.Total)))
			if filled > barLen { filled = barLen }
			bar := strings.Repeat("█", filled) + strings.Repeat("░", barLen-filled)
			
			progStr = fmt.Sprintf(" %s %d/%d (%.1f%%)%s", bar, s.Progress, s.Total, percent, etaStr)
		}
		
		msg := s.Message
		if len(msg) > 35 {
			msg = msg[:32] + "..."
		}
		if msg != "" {
			msg = " - " + msg
		}

		line := fmt.Sprintf("  %s%s%s %-22s%s%s%s\033[K\n", color, icon, RESET, s.Name, color, progStr+msg+elapsedStr, RESET)
		out += line
	}
	
	out += fmt.Sprintf("%s\n", DIM+strings.Repeat("━", 60)+RESET)
	fmt.Print(out)
}
