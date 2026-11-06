package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/term"
)

const goAIURL = "https://opencode.ai/inference/go/openai/v1/chat/completions"

type aiProfile struct {
	Model string
	URL   string
	Key   string
}

type aiProfiles struct {
	Active   int
	Profiles []aiProfile
}

func readAIProfiles() (aiProfiles, string, error) {
	var profiles aiProfiles
	dir, err := os.UserConfigDir()
	if err != nil {
		return profiles, "", err
	}
	path := filepath.Join(dir, "siphon", "ai.json")
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return profiles, path, nil
	}
	if err != nil {
		return profiles, path, err
	}
	err = json.Unmarshal(data, &profiles)
	if err == nil && (profiles.Active < 0 || (len(profiles.Profiles) > 0 && profiles.Active >= len(profiles.Profiles))) {
		err = errors.New("invalid active AI profile")
	}
	return profiles, path, err
}

func (p aiProfiles) save(path string) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	file, err := os.CreateTemp(dir, "ai-*.tmp")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	err = json.NewEncoder(file).Encode(p)
	closeErr := file.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	return os.Rename(file.Name(), path)
}

func (p aiProfile) apply() error {
	for name, value := range map[string]string{"AI_API_KEY": p.Key, "AI_API_URL": p.URL, "AI_MODEL": p.Model} {
		if err := os.Setenv(name, value); err != nil {
			return err
		}
	}
	return nil
}

func promptAIProfile(reader *bufio.Reader) (aiProfile, error) {
	var p aiProfile
	fd := int(os.Stdin.Fd())
	if !term.IsTerminal(fd) {
		return p, errors.New("AI setup requires a terminal")
	}
	for {
		fmt.Print("AI provider URL (press Enter for OpenCode Go, or paste a custom HTTPS Chat Completions URL): ")
		endpoint, err := reader.ReadString('\n')
		if err != nil {
			return p, err
		}
		p.URL = strings.TrimSpace(endpoint)
		if p.URL == "" {
			p.URL = goAIURL
		}
		parsed, err := url.Parse(p.URL)
		if err == nil && parsed.Scheme == "https" && parsed.Hostname() != "" && parsed.User == nil {
			break
		}
		fmt.Println("Enter a valid HTTPS API URL, or leave it blank for OpenCode Go. Enter your model ID at the next prompt.")
	}
	if p.URL == goAIURL {
		fmt.Print("OpenCode Go model ID (e.g. deepseek-v4.1-flash): ")
	} else {
		fmt.Print("Model ID from your AI provider: ")
	}
	model, err := reader.ReadString('\n')
	if err != nil {
		return p, err
	}
	p.Model = strings.TrimSpace(model)
	if p.Model == "" {
		return p, errors.New("model ID is required")
	}
	fmt.Print("API key (saved in local Siphon config): ")
	key, err := readMaskedKey(reader, fd)
	fmt.Println()
	if err != nil {
		return p, err
	}
	p.Key = strings.TrimSpace(string(key))
	if p.Key == "" {
		return p, errors.New("API key is required")
	}
	return p, nil
}

func readMaskedKey(reader *bufio.Reader, fd int) (string, error) {
	state, err := term.MakeRaw(fd)
	if err != nil {
		return "", err
	}
	defer term.Restore(fd, state)

	var key []rune
	for {
		ch, _, err := reader.ReadRune()
		if err != nil {
			return "", err
		}
		switch ch {
		case '\r', '\n':
			return string(key), nil
		case 3, 4:
			return "", errors.New("API key entry cancelled")
		case '\b', 127:
			if len(key) > 0 {
				key = key[:len(key)-1]
				fmt.Print("\b \b")
			}
		default:
			if ch >= ' ' {
				key = append(key, ch)
				fmt.Print("*")
			}
		}
	}
}

func manageAI(action string, reader *bufio.Reader) error {
	profiles, path, err := readAIProfiles()
	if err != nil {
		return err
	}
	switch action {
	case "setup":
		profile, err := promptAIProfile(reader)
		if err != nil {
			return err
		}
		profiles.Active = len(profiles.Profiles)
		profiles.Profiles = append(profiles.Profiles, profile)
		if err := profiles.save(path); err != nil {
			return err
		}
		return profile.apply()
	case "use", "status":
		fmt.Printf("Saved API keys: %d\n", len(profiles.Profiles))
		for i, p := range profiles.Profiles {
			active := ""
			if i == profiles.Active {
				active = " (active)"
			}
			fmt.Printf("  %d. %s%s\n", i+1, p.Model, active)
		}
		if action == "status" || len(profiles.Profiles) == 0 {
			return nil
		}
		fmt.Print("Profile number: ")
		choice, err := reader.ReadString('\n')
		if err != nil {
			return err
		}
		number, err := strconv.Atoi(strings.TrimSpace(choice))
		if err != nil || number < 1 || number > len(profiles.Profiles) {
			return errors.New("invalid profile number")
		}
		profiles.Active = number - 1
		return profiles.save(path)
	case "test":
		if len(profiles.Profiles) == 0 {
			return errors.New("run siphon ai setup first")
		}
		profile := profiles.Profiles[profiles.Active]
		if err := profile.apply(); err != nil {
			return err
		}
		if !checkAIAccess(profile.Key) {
			return errors.New("AI request failed")
		}
		fmt.Printf("AI connection OK (%s)\n", profile.Model)
		return nil
	default:
		return errors.New("usage: siphon ai setup|status|use|test")
	}
}

func loadSavedAI() error {
	if os.Getenv("AI_API_KEY") != "" {
		return nil
	}
	profiles, _, err := readAIProfiles()
	if err != nil {
		return err
	}
	if len(profiles.Profiles) == 0 {
		return nil
	}
	return profiles.Profiles[profiles.Active].apply()
}
