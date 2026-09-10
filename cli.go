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
	HideMatches   bool
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

	// usage strings are empty: flag.Usage below is the only help text ever printed
	flag.StringVar(&config.Interface, "i", defaultInterface, "")
	flag.StringVar(&config.PcapFile, "pcap", "", "")
	flag.StringVar(&config.OutputLog, "o", "", "")
	flag.BoolVar(&config.NoColor, "no-color", false, "")
	flag.BoolVar(&config.NoBanner, "no-banner", false, "")
	flag.BoolVar(&quietFlag, "q", false, "")
	flag.BoolVar(&veryQuietFlag, "qq", false, "")
	flag.BoolVar(&verboseFlag, "v", false, "")
	flag.StringVar(&showFieldStr, "show-field", "", "")
	flag.StringVar(&hideFieldStr, "hide-field", "", "")
	flag.StringVar(&config.DisplayFilter, "Y", defaultFilter, "")
	flag.StringVar(&config.TsharkPath, "tshark", "", "")
	flag.StringVar(&config.NtlmPassword, "ntlm-pass", "", "")
	flag.BoolVar(&config.HideTransport, "hide-transport", false, "")
	flag.StringVar(&compareFrameFile, "compare-frame", "", "")
	flag.StringVar(&compareFieldFile, "compare-field", "", "")
	flag.BoolVar(&config.HideMatches, "hide-matches", false, "")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, `Usage: gshark [options]

Input:
  -i string           Network interface to capture on (default "%s")
  -pcap string        PCAP file to read from instead of live capture
  -tshark string      Path to tshark executable

Output:
  -no-color           Disable colored output
  -no-banner          Suppress the gshark banner

  -Y string           Wireshark display filter (default "%s", matches everything)
  -hide-transport     Hide packets with nothing dissected above TCP/UDP (handshakes, ACKs, etc)
  -ntlm-pass string   NTLM password for decrypting sealed sessions (uses tsharks built-in ntlmssp decryption)

  -hide-field string  Lines to hide from output. Checks field names and field values. (comma separated, returns partial matches)
  -show-field string  Lines to display. Checks field names and field values. (comma separated list, returns partial matches)

  -o string           Write gshark output to log file

Verbosity:
  -qq                 Very quiet mode: only display frames with matched fields. Use with -show-field
  -q                  Quiet mode: only display protocol headers
  -v                  Display all fields including transport/network layers (frame/eth/ip/tcp/udp)

Compare:
  Create a template from saved gshark output (-o), then run gshark against a new capture.

  -compare-field string  Match frames of any protocol carrying at least one starred field. Prints only the marked fields with the template value diffed.
    *name: value    Diff field value against template
    **name: value   Require this field value to exactly match the template value in order to print this field
  
  -compare-frame string  Full-frame diff. All fields in the frame are diffed against the template. 
    **name: value   Marks an alignment field. This field(s) should be defined to pick matching frames from the capture.

  -hide-matches          With either compare mode, hide fields whose value equals the template.

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

	// -hide-transport - applied inside tshark's display filter
	if config.HideTransport {
		config.DisplayFilter = "(" + config.DisplayFilter + `) and not frame.protocols matches ":(tcp|udp)$"`
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

	if config.HideTransport {
		fmt.Println("[-] Hiding transport-only packets (TCP handshakes, ACKs, etc.)")
	}

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
		if config.CompareMode == "frame" {
			// frame mode is a full-frame diff
			fmt.Printf("[-] Compare frame mode: %s (%d template frame(s), full-frame diff)\n",
				config.CompareFile, len(compareTemplates))
			for _, tmpl := range compareTemplates {
				var keys []string
				for _, f := range tmpl.Fields {
					if f.ExactMatch {
						keys = append(keys, f.Name+"="+f.Value)
					}
				}
				if len(keys) > 0 {
					fmt.Printf("    - [%s] key: %s\n", strings.ToUpper(tmpl.Protocol), strings.Join(keys, ", "))
				} else {
					fmt.Printf("    - [%s] no key (aligned by best field overlap)\n", strings.ToUpper(tmpl.Protocol))
				}
			}
		} else {
			totalCompare := countCompareFields(compareTemplates)
			fmt.Printf("[-] Compare field mode: %s (%d compared fields)\n",
				config.CompareFile, totalCompare)
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
		if config.HideMatches {
			fmt.Println("    (hide-matches: showing only differences)")
		}
	}
	if config.PcapFile != "" {
		fmt.Printf("[-] Reading from file: %s\n", config.PcapFile)
	}
}
