// cli switches

package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

// deafult wireshark filter to show when one isn't specified
var defaultFilter = "frame"

var config Config

type Config struct {
	Interface     string
	PcapFile      string
	OutputLog     string
	Verbose       int
	DisplayFilter string
	NoColor       bool
	NoBanner      bool
	ShowFields    []string
	HideFields    []string
	Quiet         int
	TsharkPath    string
	NtlmPassword  string
	HideTransport bool
	CompareMode   string
	CompareFile   string
}

func printBanner() {
	banner := `               __                  __
   ____  _____|  |__ _____ _______|  | __
  / ___\/  ___/  |  \\__  \_  __ \  |/ /
 / /_/  |___ \|   Y  \/ __ \|  | \/    <
 \___  /____  >___|  (____  /__|  |__|_ \
/_____/     \/     \/     \/           \/
`
	fmt.Println(banner)
}

func parseFlags() Config {
	defaultInterface := "eth0"
	if runtime.GOOS == "windows" {
		defaultInterface = "Ethernet"
	}

	var showFieldStr, hideFieldStr string
	var compareFrameFile, compareFieldFile string
	var verboseFlag, quietFlag, veryQuietFlag bool

	flag.StringVar(&config.Interface, "i", defaultInterface, "Network interface to capture on")
	flag.StringVar(&config.PcapFile, "pcap", "", "PCAP file to read from instead of live capture")
	flag.StringVar(&config.OutputLog, "o", "", "Output to log file")
	flag.BoolVar(&config.NoColor, "no-color", false, "Disable colored output")
	flag.BoolVar(&config.NoBanner, "no-banner", false, "Suppress the gshark banner")
	flag.BoolVar(&quietFlag, "q", false, "Quiet mode: only display protocol headers")
	flag.BoolVar(&veryQuietFlag, "qq", false, "Very quiet mode: only display packets with matched fields")
	flag.BoolVar(&verboseFlag, "v", false, "Display all fields including transport/network layers")
	flag.StringVar(&showFieldStr, "show-field", "", "Additional fields to display (comma separated, partial match)")
	flag.StringVar(&hideFieldStr, "hide-field", "", "Fields to hide from output (comma separated, partial match)")
	flag.StringVar(&config.DisplayFilter, "Y", defaultFilter, "Wireshark display filter")
	flag.StringVar(&config.TsharkPath, "tshark", "", "Path to tshark executable")
	flag.StringVar(&config.NtlmPassword, "ntlm-pass", "", "NTLM password for decrypting sealed sessions")
	flag.BoolVar(&config.HideTransport, "hide-transport", false, "Hide transport-only packets (TCP handshakes, ACKs, etc.)")
	flag.StringVar(&compareFrameFile, "compare-frame", "", "Template: match by protocol + starred fields, show all fields")
	flag.StringVar(&compareFieldFile, "compare-field", "", "Template: match and diff only starred fields across all protocols")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, `Usage: gshark [options]

Input:
  -i string           Network interface to capture on (default "%s")
  -pcap string        PCAP file to read from instead of live capture
  -tshark string      Path to tshark executable

Output:
  -Y string           Wireshark display filter (default "%s")
  -hide-transport     Hide transport-only packets (TCP handshakes, ACKs, etc.)
  -o string           Write gshark output to log file

  -no-color           Disable colored output
  -no-banner          Suppress the gshark banner

Verbosity:
  -show-field string  Lines to display. Checks field names and field values. (comma separated list, returns partial matches)
  -hide-field string  Lines to hide from output. Checks field names and field values. (comma separated, returns partial matches)
  -qq                 Very quiet mode: only display packets with matched fields. Use with -show-field
  -q                  Quiet mode: only display protocol headers
  -v                  Display all fields including transport/network layers (frame/eth/ip/tcp/udp)

Compare:
  -compare-frame string  Template: match by protocol + all starred fields, show all fields
  -compare-field string  Template: match and diff only starred fields across all protocols
                         Star a field by putting * (diff) or ** (exact value match) in front of its name

Decryption:
  -ntlm-pass string   NTLM password for decrypting sealed sessions (limited support)
`, defaultInterface, defaultFilter)
	}

	flag.Parse()

	if showFieldStr != "" {
		for _, field := range strings.Split(showFieldStr, ",") {
			if trimmed := strings.TrimSpace(field); trimmed != "" {
				config.ShowFields = append(config.ShowFields, trimmed)
			}
		}
	}

	if hideFieldStr != "" {
		for _, field := range strings.Split(hideFieldStr, ",") {
			if trimmed := strings.TrimSpace(field); trimmed != "" {
				config.HideFields = append(config.HideFields, trimmed)
			}
		}
	}

	if veryQuietFlag {
		config.Quiet = 2
	} else if quietFlag {
		config.Quiet = 1
	}

	if verboseFlag {
		config.Verbose = 1
	}

	if compareFrameFile != "" && compareFieldFile != "" {
		fmt.Fprintf(os.Stderr, "[!] Cannot use both -compare-frame and -compare-field\n")
		os.Exit(1)
	}
	if compareFrameFile != "" {
		config.CompareMode = "frame"
		config.CompareFile = compareFrameFile
	} else if compareFieldFile != "" {
		config.CompareMode = "field"
		config.CompareFile = compareFieldFile
	}

	if config.Quiet > 0 && config.Verbose > 0 {
		fmt.Fprintf(os.Stderr, "[!] Cannot combine quiet (-q/-qq) and verbose (-v) modes\n")
		os.Exit(1)
	}
	if config.Quiet == 2 && len(config.ShowFields) == 0 {
		fmt.Fprintf(os.Stderr, "[!] -qq requires -show-field to specify which fields to match\n")
		os.Exit(1)
	}
	if config.CompareMode == "field" && (config.Quiet > 0 || config.Verbose > 0) {
		fmt.Fprintf(os.Stderr, "[!] Cannot combine -compare-field with verbosity flags (-q/-qq/-v)\n")
		os.Exit(1)
	}
	if config.CompareMode == "frame" && config.Quiet > 0 {
		fmt.Fprintf(os.Stderr, "[!] Cannot combine -compare-frame with quiet flags (-q/-qq)\n")
		os.Exit(1)
	}

	// validate pcap file exists before passing to tshark.
	if config.PcapFile != "" {
		config.PcapFile = filepath.Clean(config.PcapFile)
		if _, err := os.Stat(config.PcapFile); err != nil {
			fmt.Fprintf(os.Stderr, "[!] PCAP file not found: %s\n", config.PcapFile)
			os.Exit(1)
		}
	}

	if config.OutputLog != "" {
		config.OutputLog = filepath.Clean(config.OutputLog)
	}

	if config.TsharkPath != "" {
		config.TsharkPath = filepath.Clean(config.TsharkPath)
	}

	if config.CompareMode != "" {
		config.CompareFile = filepath.Clean(config.CompareFile)
		var err error
		compareTemplates, err = parseCompareFile(config.CompareFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[!] Error parsing compare file: %v\n", err)
			os.Exit(1)
		}
		if countCompareFields(compareTemplates) == 0 {
			fmt.Fprintf(os.Stderr, "[!] Warning: no fields are marked for comparison in %s (put * or ** in front of a field name)\n", config.CompareFile)
		}
	}

	return config
}

// locate tshark
func findTshark(customPath string) string {
	if customPath != "" {
		if _, err := os.Stat(customPath); err != nil {
			fmt.Fprintf(os.Stderr, "[!] Specified tshark not found: %s\n", customPath)
			os.Exit(1)
		}
		return customPath
	}

	if runtime.GOOS == "windows" {
		for _, path := range []string{
			`C:\Program Files\Wireshark\tshark.exe`,
			`C:\Program Files (x86)\Wireshark\tshark.exe`,
		} {
			if _, err := os.Stat(path); err == nil {
				return path
			}
		}
		if _, err := exec.LookPath("tshark.exe"); err != nil {
			fmt.Fprintf(os.Stderr, "[!] tshark not found. Install Wireshark or specify path with -tshark\n")
			os.Exit(1)
		}
		return "tshark.exe"
	}

	if _, err := exec.LookPath("tshark"); err != nil {
		fmt.Fprintf(os.Stderr, "[!] tshark not found in PATH. Install wireshark-cli or specify path with -tshark\n")
		os.Exit(1)
	}
	return "tshark"
}

// printStartupInfo logs the active configuration to stdout.
func printStartupInfo() {
	fmt.Printf("[-] Display filter: %s\n", config.DisplayFilter)

	if config.Verbose == 1 {
		fmt.Println("[-] Verbose mode: Displaying all fields (all layers)")
	}

	switch config.Quiet {
	case 1:
		fmt.Println("[-] Quiet mode: Showing protocol headers only")
	case 2:
		fmt.Println("[-] Very quiet mode: Only showing packets with matched fields")
	}

	if len(config.ShowFields) > 0 {
		fmt.Printf("[-] Showing fields containing: %s\n", strings.Join(config.ShowFields, ", "))
	}

	if len(config.HideFields) > 0 {
		fmt.Printf("[-] Hiding fields containing: %s\n", strings.Join(config.HideFields, ", "))
	}

	if config.NtlmPassword != "" {
		fmt.Println("[-] NTLM decryption enabled")
	}
	if config.CompareMode != "" && len(compareTemplates) > 0 {
		totalCompare := countCompareFields(compareTemplates)
		modeLabel := "frame"
		if config.CompareMode == "field" {
			modeLabel = "field"
		}
		fmt.Printf("[-] Compare %s mode: %s (%d compared fields)\n",
			modeLabel, config.CompareFile, totalCompare)
		for _, tmpl := range compareTemplates {
			for _, f := range tmpl.Fields {
				if f.Compare {
					if f.ExactMatch {
						fmt.Printf("    - %s: %s (exact)\n", f.Name, f.Value)
					} else {
						fmt.Printf("    - %s (diff)\n", f.Name)
					}
				}
			}
		}
	}
	if config.PcapFile != "" {
		fmt.Printf("[-] Reading from file: %s\n", config.PcapFile)
	}
}
