package main

import (
	"path/filepath"
	"testing"
)

func TestSavedAIProfileSelection(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("APPDATA", dir)
	t.Setenv("XDG_CONFIG_HOME", dir)
	t.Setenv("HOME", dir)
	t.Setenv("AI_API_KEY", "")
	path := filepath.Join(dir, "siphon", "ai.json")
	p := aiProfiles{Profiles: []aiProfile{
		{Model: "first", URL: goAIURL, Key: "fake-first"},
		{Model: "second", URL: goAIURL, Key: "fake-second"},
	}}
	if err := p.save(path); err != nil {
		t.Fatal(err)
	}
	p.Active = 1
	if err := p.save(path); err != nil {
		t.Fatal(err)
	}
	if err := loadSavedAI(); err != nil {
		t.Fatal(err)
	}
	loaded, _, err := readAIProfiles()
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Active != 1 || len(loaded.Profiles) != 2 {
		t.Fatal("saved profile selection was lost")
	}
}
