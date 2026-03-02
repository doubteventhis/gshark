package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"time"
	"sort"
	"strings"
	"syscall"

	"github.com/fatih/color"
)

// defaultFilter is the Wireshark display filter applied when no -Y flag is given.
//var defaultFilter = "kerberos or smb or smb2 or llmnr or nbns or mdns or dns or dhcpv6 or ldap or http or icmpv6 or dcerpc or cldap or ssdp"
var defaultFilter = "frame"

// defaultProtocolOrder is the display order assigned to unknown protocol layers.
const defaultProtocolOrder = 50

// config holds runtime settings parsed from command-line flags.
// It is written once during flag parsing and read-only thereafter.
var config Config

// Config holds all runtime settings parsed from command-line flags.
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
	JSONOutput    string
	CompareMode   string // "", "frame", or "field"
	CompareFile   string
}

// TSharkPacket is the top-level JSON structure emitted by tshark -T json.
type TSharkPacket struct {
	Source PacketSource `json:"_source"`
}

// PacketSource contains the protocol layers decoded from a single packet.
type PacketSource struct {
	Layers map[string]interface{} `json:"layers"`
}

// ProtocolDef defines a supported protocol.
// To add a new protocol, append an entry to the protocols slice below.
type ProtocolDef struct {
	Key          string       // tshark JSON layer name (e.g. "smb2", "dns")
	Color        *color.Color // terminal color for this protocol's output
	Fields       []string     // fields to display in default verbosity mode
	IncludeAuth  bool         // if true, append shared NTLM + Kerberos fields
	DisplayOrder int          // output ordering: lower = closer to wire, printed first
}

// FieldEntry is a single name-value pair extracted from a packet layer.
type FieldEntry struct {
	Name  string
	Value string
}

// CompareField is a single field from a compare template file.
type CompareField struct {
	Name       string // field name (e.g. "http.response.code")
	Value      string // expected value (only meaningful when Compare is true)
	Compare    bool   // true if this field had a * suffix (field presence required, value diffed)
	ExactMatch bool   // true if this field had a ** suffix (field AND value must match exactly)
}

// CompareTemplate holds a parsed compare template for field-level diffing.
type CompareTemplate struct {
	Protocol string         // lowercase protocol name (e.g. "http")
	Fields   []CompareField // all fields from the template
}

// compareTemplates holds parsed compare templates, nil if -compare not used.
var compareTemplates []*CompareTemplate

// ntlmFields are the authentication fields shown for NTLM traffic.
var ntlmFields = []string{
	"ntlmssp.messagetype",
	"ntlmssp.auth.username",
	"ntlmssp.ntlmserverchallenge",
	"ntlmssp.authenticate.mic",
	"ntlmssp.auth.sesskey",
	"ntlmssp.challenge.target_info.dns_computer_name",
	"ntlmssp.ntlmv2_response.channel_bindings",
	"ntlmssp.ntlmv2_response.target_name",
	"ntlmssp.ntlmv2_response.dns_computer_name",
	"ntlmssp.ntlmv2_response.ntproofstr",
	"ntlmssp.auth.ntresponse",
}

// kerberosFields are the authentication fields shown for Kerberos traffic.
var kerberosFields = []string{
	"kerberos.msg_type",
	"kerberos.encryptedTicketData_cipher",
	"kerberos.encryptedKDCREPData_cipher",
	"kerberos.CNameString",
	"kerberos.SNameString",
	"kerberos.etype",
}

// protocols defines all supported protocols in priority order.
// Priority determines which protocol label is shown when multiple layers exist
// in one packet (first match wins). DisplayOrder controls the output ordering
// of fields (lower = closer to wire, printed first).
var protocols = []ProtocolDef{
	{Key: "ntlmssp", Color: color.New(color.FgHiRed), DisplayOrder: 31, Fields: ntlmFields},
	{Key: "kerberos", Color: color.New(color.FgMagenta), DisplayOrder: 30, Fields: kerberosFields},
	{Key: "smb2", Color: color.New(color.FgRed), DisplayOrder: 25, IncludeAuth: true, Fields: []string{
		"smb2.cmd",
		"smb2.sec_mode",
		"spnego.negResult",
		"srvsvc.srvsvc_NetShareInfo1.name",
	}},
	{Key: "smb", Color: color.New(color.FgRed), DisplayOrder: 25, IncludeAuth: true, Fields: []string{
		"smb.cmd",
		"smb2.cmd",
		"spnego.negResult",
	}},
	{Key: "ldap", Color: color.RGB(255, 140, 0), DisplayOrder: 24, IncludeAuth: true, Fields: []string{
		"ldap.protocolOp",
		"ldap.bindResponse_resultCode",
		"ldap.assertionValue",
		"ldap.authentication",
	}},
	{Key: "ldaps", Color: color.RGB(255, 140, 0), DisplayOrder: 24, IncludeAuth: true},
	{Key: "http", Color: color.New(color.FgCyan), DisplayOrder: 23, IncludeAuth: true, Fields: []string{
		"http.authorization",
		"http.request.method",
		"http.request.full_uri",
		"http.response.code",
		"http.www_authenticate",
		"http.user_agent",
		"http.server",
	}},
	{Key: "dns", Color: color.RGB(65, 105, 225), DisplayOrder: 12, Fields: []string{
		"dns.a",
		"dns.qry.type",
		"dns.resp.type",
		"dns.qry.name",
		"dns.resp.name",
	}},
	{Key: "llmnr", Color: color.RGB(100, 149, 237), DisplayOrder: 12, Fields: []string{
		"dns.a",
		"dns.qry.type",
		"dns.qry.name",
		"dns.aaaa",
		"dns.resp.ttl",
	}},
	{Key: "nbns", Color: color.RGB(0, 191, 255), DisplayOrder: 12, Fields: []string{
		"dns.qry.name",
		"dns.resp.name",
		"dns.a",
	}},
	{Key: "mdns", Color: color.RGB(135, 206, 250), DisplayOrder: 12, Fields: []string{
		"dns.qry.name",
		"dns.resp.name",
		"dns.a",
		"dns.aaaa",
	}},
	{Key: "dhcpv6", Color: color.New(color.FgGreen), DisplayOrder: 13, Fields: []string{
		"dhcpv6.msgtype",
		"dhcpv6.duid.type",
	}},
	{Key: "dcerpc", Color: color.New(color.FgHiCyan), DisplayOrder: 20, Fields: []string{
		"dcerpc.op",
		"dcerpc.call_id",
	}},
	{Key: "icmpv6", Color: color.RGB(255, 100, 200), DisplayOrder: 11, Fields: []string{
		"icmpv6.type",
		"icmpv6.opt.rdnss",
		"icmpv6.opt.rdnss.lifetime",
		"icmpv6.opt.linkaddr",
	}},
	{Key: "arp", Color: color.New(color.FgYellow), DisplayOrder: 10, Fields: []string{
		"arp.opcode",
		"arp.src.proto_ipv4",
		"arp.dst.proto_ipv4",
	}},
	{Key: "ssdp", Color: color.New(color.FgHiYellow), DisplayOrder: 23, Fields: []string{
		"http.request.method",
		"http.request.full_uri",
	}},
	{Key: "modbus", Color: color.New(color.FgHiGreen), DisplayOrder: 21},
	{Key: "nmf", Color: color.New(color.FgHiMagenta), DisplayOrder: 22},
	{Key: "tls", Color: color.New(color.FgHiBlue), DisplayOrder: 6, Fields: []string{
		"tls.record.version",
		"tls.record.content_type",
	}},
	{Key: "tcp", Color: color.New(color.FgWhite), DisplayOrder: 3},
}

// Derived lookup tables built from the protocols slice during init().
var (
	protocolColors     map[string]*color.Color // protocol key -> terminal color
	protocolPriorities []string                // protocol keys in detection priority order
	defaultFields      map[string][]string     // protocol key -> fields to show in default mode
	layerDisplayOrder  map[string]int          // layer name -> display order position
)

// skipLayers lists transport/network layers excluded from output unless -vv is used.
var skipLayers = map[string]bool{
	"frame": true, "frame_raw": true,
	"eth": true, "eth_raw": true,
	"ip": true, "ipv6": true, "ip_raw": true, "ipv6_raw": true,
	"tcp": true, "udp": true, "tcp_raw": true, "udp_raw": true,
}

func init() {
	protocolColors = make(map[string]*color.Color)
	defaultFields = make(map[string][]string)

	// Base display order for transport/network layers.
	layerDisplayOrder = map[string]int{
		"frame": 0, "frame_raw": 0,
		"eth": 1, "eth_raw": 1,
		"ip": 2, "ipv6": 2, "ip_raw": 2, "ipv6_raw": 2,
		"tcp": 3, "udp": 3, "tcp_raw": 3, "udp_raw": 3,
	}

	for _, p := range protocols {
		protocolColors[p.Key] = p.Color
		protocolPriorities = append(protocolPriorities, p.Key)
		layerDisplayOrder[p.Key] = p.DisplayOrder

		fields := make([]string, len(p.Fields))
		copy(fields, p.Fields)
		if p.IncludeAuth {
			fields = append(fields, ntlmFields...)
			fields = append(fields, kerberosFields...)
		}
		if len(fields) > 0 {
			defaultFields[p.Key] = fields
		}
	}
}

// ---------------------------------------------------------------------------
// CLI setup
// ---------------------------------------------------------------------------

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

// parseFlags registers and parses all command-line flags, returning the
// resolved config. Exits with an error if flag values are invalid.
func parseFlags() Config {
	defaultInterface := "eth0"
	if runtime.GOOS == "windows" {
		defaultInterface = "Ethernet"
	}

	var showFieldStr, hideFieldStr string
	var compareFrameFile, compareFieldFile string
	var verboseFlag, veryVerboseFlag, quietFlag, veryQuietFlag bool

	flag.StringVar(&config.Interface, "i", defaultInterface, "Network interface to capture on")
	flag.StringVar(&config.PcapFile, "pcap", "", "PCAP file to read from instead of live capture")
	flag.StringVar(&config.OutputLog, "o", "", "Output to log file")
	flag.BoolVar(&config.NoColor, "no-color", false, "Disable colored output")
	flag.BoolVar(&config.NoBanner, "no-banner", false, "Suppress the gshark banner")
	flag.BoolVar(&quietFlag, "q", false, "Quiet mode: only display protocol headers")
	flag.BoolVar(&veryQuietFlag, "qq", false, "Very quiet mode: only display packets with matched fields")
	flag.BoolVar(&verboseFlag, "v", false, "Display all fields for application layer protocols")
	flag.BoolVar(&veryVerboseFlag, "vv", false, "Display all fields including transport/network layers")
	flag.StringVar(&showFieldStr, "show-field", "", "Additional fields to display (comma separated, partial match)")
	flag.StringVar(&hideFieldStr, "hide-field", "", "Fields to hide from output (comma separated, partial match)")
	flag.StringVar(&config.DisplayFilter, "Y", defaultFilter, "Wireshark display filter")
	flag.StringVar(&config.TsharkPath, "tshark", "", "Path to tshark executable")
	flag.StringVar(&config.NtlmPassword, "ntlm-pass", "", "NTLM password for decrypting sealed sessions")
	flag.BoolVar(&config.HideTransport, "hide-transport", false, "Hide transport-only packets (TCP handshakes, ACKs, etc.)")
	flag.StringVar(&config.JSONOutput, "w", "", "Write raw pcap output to file")
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

  -w string           Write raw pcap output to file
  -o string           Write gshark output to log file
  
  -no-color           Disable colored output
  -no-banner          Suppress the gshark banner

Verbosity:
  -show-field string  Lines to display. Checks field names and field values. (comma separated list, returns partial matches)
  -hide-field string  Lines to hide from output. Checks field names and field values. (comma separated, returns partial matches)
  -qq                 Very quiet mode: only display packets with matched fields. Use with -show-field
  -q                  Quiet mode: only display protocol headers
  -v                  Display all fields for application layer protocols
  -vv                 Display all fields including transport/network layers

Compare:
  -compare-frame string  Template: match by protocol + all starred fields, show all fields
  -compare-field string  Template: match and diff only starred fields across all protocols
                         Use * to diff a field, ** to require exact value match

Decryption:
  -ntlm-pass string   NTLM password for decrypting sealed sessions (limited support)
`, defaultInterface, defaultFilter)
	}

	flag.Parse()

	// Parse show-field values.
	if showFieldStr != "" {
		for _, field := range strings.Split(showFieldStr, ",") {
			if trimmed := strings.TrimSpace(field); trimmed != "" {
				config.ShowFields = append(config.ShowFields, trimmed)
			}
		}
	}

	// Parse hide-field values.
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

	// Parse verbosity level.
	if veryVerboseFlag {
		config.Verbose = 2
	} else if verboseFlag {
		config.Verbose = 1
	}

	// Resolve compare mode from flags.
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

	// Validate flag combinations.
	if config.Quiet > 0 && config.Verbose > 0 {
		fmt.Fprintf(os.Stderr, "[!] Cannot combine quiet (-q/-qq) and verbose (-v/-vv) modes\n")
		os.Exit(1)
	}
	if config.Quiet == 2 && len(config.ShowFields) == 0 {
		fmt.Fprintf(os.Stderr, "[!] -qq requires -show-field to specify which fields to match\n")
		os.Exit(1)
	}
	if config.JSONOutput != "" && config.PcapFile != "" {
		fmt.Fprintf(os.Stderr, "[!] -w is only supported for live capture, not with -pcap\n")
		os.Exit(1)
	}
	if config.CompareMode == "field" && (config.Quiet > 0 || config.Verbose > 0) {
		fmt.Fprintf(os.Stderr, "[!] Cannot combine -compare-field with verbosity flags (-q/-qq/-v/-vv)\n")
		os.Exit(1)
	}
	if config.CompareMode == "frame" && config.Quiet > 0 {
		fmt.Fprintf(os.Stderr, "[!] Cannot combine -compare-frame with quiet flags (-q/-qq)\n")
		os.Exit(1)
	}

	// Validate pcap file exists before passing to tshark.
	if config.PcapFile != "" {
		config.PcapFile = filepath.Clean(config.PcapFile)
		if _, err := os.Stat(config.PcapFile); err != nil {
			fmt.Fprintf(os.Stderr, "[!] PCAP file not found: %s\n", config.PcapFile)
			os.Exit(1)
		}
	}

	// Sanitize output log path.
	if config.OutputLog != "" {
		config.OutputLog = filepath.Clean(config.OutputLog)
	}

	// Sanitize pcap output path.
	if config.JSONOutput != "" {
		config.JSONOutput = filepath.Clean(config.JSONOutput)
	}

	// Sanitize tshark path.
	if config.TsharkPath != "" {
		config.TsharkPath = filepath.Clean(config.TsharkPath)
	}

	// Parse compare template file.
	if config.CompareMode != "" {
		config.CompareFile = filepath.Clean(config.CompareFile)
		var err error
		compareTemplates, err = parseCompareFile(config.CompareFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[!] Error parsing compare file: %v\n", err)
			os.Exit(1)
		}
	}

	return config
}

// findTshark locates the tshark executable. If a custom path is provided via
// -tshark, it is validated. Otherwise the function searches standard locations.
// Exits with an error if tshark cannot be found.
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

	switch config.Verbose {
	case 1:
		fmt.Println("[-] Verbose mode: Displaying all application layer fields")
	case 2:
		fmt.Println("[-] Very verbose mode: Displaying all fields (all layers)")
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
		totalCompare := 0
		for _, tmpl := range compareTemplates {
			for _, f := range tmpl.Fields {
				if f.Compare {
					totalCompare++
				}
			}
		}
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

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

func main() {
	config = parseFlags()

	if config.NoColor {
		color.NoColor = true
	}

	if !config.NoBanner {
		printBanner()
	}

	printStartupInfo()

	// Build tshark arguments.
	tsharkArgs := []string{
		"-l",
		"-T", "json",
		"-Y", config.DisplayFilter,
	}
	if config.PcapFile != "" {
		tsharkArgs = append([]string{"-r", config.PcapFile}, tsharkArgs...)
	} else {
		tsharkArgs = append([]string{"-i", config.Interface}, tsharkArgs...)
	}

	// Append decryption options.
	if config.NtlmPassword != "" {
		tsharkArgs = append(tsharkArgs, "-o", "ntlmssp.nt_password:"+config.NtlmPassword)
	}

	// Open log file if requested.
	var logFile *os.File
	if config.OutputLog != "" {
		var err error
		logFile, err = os.Create(config.OutputLog)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[!] Error creating log file: %v\n", err)
			os.Exit(1)
		}
		defer logFile.Close()
		// Write UTF-8 BOM so Windows tools display Unicode correctly.
		logFile.Write([]byte{0xEF, 0xBB, 0xBF})
		fmt.Printf("[-] Sending output to %s\n", config.OutputLog)
	}

	// Locate and start tshark.
	tsharkCmd := findTshark(config.TsharkPath)

	// Start a separate process for raw pcap capture if -w is set.
	// On Windows, use tshark. On Linux/Mac, use tcpdump (tshark's dumpcap
	// drops privileges even as root, causing "Permission denied").
	var pcapCmd *exec.Cmd
	var pcapLabel string
	if config.JSONOutput != "" && config.PcapFile == "" {
		if runtime.GOOS == "windows" {
			pcapCmd = exec.Command(tsharkCmd, "-i", config.Interface, "-w", config.JSONOutput)
			pcapLabel = "tshark-pcap"
		} else {
			pcapCmd = exec.Command("tcpdump", "-i", config.Interface, "-w", config.JSONOutput)
			pcapLabel = "tcpdump"
		}
		pcapStderr, _ := pcapCmd.StderrPipe()
		if err := pcapCmd.Start(); err != nil {
			fmt.Fprintf(os.Stderr, "[!] Error starting pcap writer: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("[-] Writing pcap to %s\n", config.JSONOutput)
		go func() {
			scanner := bufio.NewScanner(pcapStderr)
			for scanner.Scan() {
				if line := scanner.Text(); line != "" {
					fmt.Fprintf(os.Stderr, "[%s] %s\n", pcapLabel, line)
				}
			}
		}()
	}

	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.Command(tsharkCmd, tsharkArgs...)
	} else {
		cmd = exec.Command("stdbuf", append([]string{"-oL", tsharkCmd}, tsharkArgs...)...)
	}

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		fmt.Fprintf(os.Stderr, "[!] Error creating stdout pipe: %v\n", err)
		os.Exit(1)
	}

	stderr, err := cmd.StderrPipe()
	if err != nil {
		fmt.Fprintf(os.Stderr, "[!] Error creating stderr pipe: %v\n", err)
		os.Exit(1)
	}

	if err := cmd.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "[!] Error starting tshark: %v\n", err)
		os.Exit(1)
	}

	// On SIGINT/SIGTERM, kill both tshark processes.
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigChan
		// Stop pcap writer gracefully so it flushes the pcap file.
		if pcapCmd != nil && pcapCmd.Process != nil {
			if runtime.GOOS == "windows" {
				pcapCmd.Process.Kill()
			} else {
				pcapCmd.Process.Signal(syscall.SIGTERM)
			}
		}
		if cmd.Process != nil {
			cmd.Process.Kill()
		}
	}()

	// Drain tshark stderr in the background.
	go func() {
		scanner := bufio.NewScanner(stderr)
		for scanner.Scan() {
			if line := scanner.Text(); line != "" {
				fmt.Fprintln(os.Stderr, "[tshark] "+line)
			}
		}
		if err := scanner.Err(); err != nil && !strings.Contains(err.Error(), "file already closed") {
			fmt.Fprintf(os.Stderr, "[!] Error reading tshark stderr: %v\n", err)
		}
	}()

	// Process packets until tshark exits or is killed.
	processJSONOutput(bufio.NewReader(stdout), logFile)

	if err := cmd.Wait(); err != nil {
		// Suppress the "signal: killed" error from our own signal handler.
		if cmd.ProcessState != nil && cmd.ProcessState.ExitCode() == -1 {
			if pcapCmd != nil {
				pcapCmd.Wait()
			}
			return
		}
		fmt.Fprintf(os.Stderr, "[!] tshark exited with error: %v\n", err)
		os.Exit(1)
	}
	if pcapCmd != nil {
		pcapCmd.Wait()
	}
}

// ---------------------------------------------------------------------------
// Packet processing
// ---------------------------------------------------------------------------

// processJSONOutput reads tshark's JSON array stream from stdout, decodes each
// packet, formats it, and prints it to the terminal. If logFile is non-nil,
// a copy with ANSI codes stripped is written to the log.
func processJSONOutput(stdout *bufio.Reader, logFile *os.File) {
	decoder := json.NewDecoder(stdout)

	// Expect opening bracket of the JSON array.
	token, err := decoder.Token()
	if err != nil {
		fmt.Fprintf(os.Stderr, "[!] Error reading tshark output: %v\n", err)
		return
	}
	if delim, ok := token.(json.Delim); !ok || delim != '[' {
		fmt.Fprintf(os.Stderr, "[!] Expected JSON array from tshark, got: %v\n", token)
		return
	}

	for decoder.More() {
		var packet TSharkPacket
		if err := decoder.Decode(&packet); err != nil {
			if err.Error() == "unexpected EOF" || err.Error() == "EOF" {
				return
			}
			fmt.Fprintf(os.Stderr, "[!] Error decoding packet: %v\n", err)
			continue
		}

		output := formatPacketJSON(packet)
		if output == "" {
			continue
		}
		fmt.Print(output)

		if logFile != nil {
			if _, err := logFile.WriteString(stripAnsiCodes(output)); err != nil {
				fmt.Fprintf(os.Stderr, "[!] Error writing to log file: %v\n", err)
			}
		}
	}
}

// ---------------------------------------------------------------------------
// Packet formatting
// ---------------------------------------------------------------------------

// formatPacketJSON builds a colorized, tree-formatted string for a single packet.
// The output includes a protocol header line and field entries based on the
// current verbosity level.
func formatPacketJSON(packet TSharkPacket) string {
	var output strings.Builder
	layers := packet.Source.Layers

	// Extract connection info from frame/ip/tcp/udp layers.
	// Fall back to ethernet MACs for non-IP protocols like ARP.
	srcIP := extractField(layers, "ip.src")
	dstIP := extractField(layers, "ip.dst")
	if srcIP == "" {
		srcIP = extractField(layers, "ipv6.src")
		dstIP = extractField(layers, "ipv6.dst")
	}
	if srcIP == "" {
		srcIP = extractField(layers, "eth.src")
		dstIP = extractField(layers, "eth.dst")
	}

	srcPort := extractField(layers, "tcp.srcport")
	dstPort := extractField(layers, "tcp.dstport")
	tcpStream := extractField(layers, "tcp.stream")
	isUDP := false

	if srcPort == "" {
		srcPort = extractField(layers, "udp.srcport")
		dstPort = extractField(layers, "udp.dstport")
		if srcPort != "" {
			isUDP = true
		}
	}

	// Determine primary protocol (highest-priority layer present).
	// Suppress transport-only packets (TCP handshakes, ACKs, etc.)
	// unless very verbose mode is enabled.
	protocolKey, protocolName := detectProtocol(layers)
	if config.HideTransport && skipLayers[protocolKey] {
		return ""
	}

	protocolColor := protocolColors[protocolKey]
	if protocolColor == nil {
		protocolColor = color.New(color.FgCyan)
	}

	// Build endpoint strings.
	srcEndpoint := srcIP
	if srcPort != "" {
		srcEndpoint = srcIP + ":" + srcPort
	}
	dstEndpoint := dstIP
	if dstPort != "" {
		dstEndpoint = dstIP + ":" + dstPort
	}

	// Extract and format packet timestamp from frame layer.
	timestamp := ""
	if timeStr := extractField(layers, "frame.time_epoch"); timeStr != "" {
		if t, err := time.Parse(time.RFC3339Nano, timeStr); err == nil {
			timestamp = t.Local().Format("2006-01-02 15:04:05.000")
		} else if epochFloat, err := strconv.ParseFloat(timeStr, 64); err == nil {
			sec := int64(epochFloat)
			nsec := int64((epochFloat - float64(sec)) * 1e9)
			timestamp = time.Unix(sec, nsec).Format("2006-01-02 15:04:05.000")
		}
	}

	// Write the protocol header line with colored components.
	grey := color.RGB(140, 140, 140)
	white := color.New(color.FgHiWhite, color.Bold)

	var transport string
	if tcpStream != "" {
		transport = fmt.Sprintf(" %s%s%s", white.Sprint("["), grey.Sprintf("Stream: %s", tcpStream), white.Sprint("]"))
	} else if isUDP {
		transport = fmt.Sprintf(" %s%s%s", white.Sprint("["), grey.Sprint("UDP"), white.Sprint("]"))
	}

	var timestampStr string
	if timestamp != "" {
		timestampStr = fmt.Sprintf(" %s%s%s", white.Sprint("["), grey.Sprint(timestamp), white.Sprint("]"))
	}

	headerLine := fmt.Sprintf("%s%s%s %s%s %s %s%s%s%s\n",
		white.Sprint("["), protocolColor.Sprint(strings.ToUpper(protocolName)), white.Sprint("]"),
		white.Sprint("["), white.Sprint(srcEndpoint), white.Sprint("->"), white.Sprint(dstEndpoint), white.Sprint("]"),
		timestampStr, transport)

	// Collect fields based on verbosity level.
	var matchedFields []FieldEntry

	switch config.Verbose {
	case 0:
		if config.Quiet == 0 {
			matchedFields = collectDefaultFields(layers, protocolKey)
		}
		if len(config.ShowFields) > 0 {
			matchedFields = append(matchedFields, collectShowFields(layers, config.ShowFields)...)
		}
	case 1:
		matchedFields = collectAllFields(layers, false)
		if len(config.ShowFields) > 0 {
			matchedFields = append(matchedFields, collectShowFields(layers, config.ShowFields)...)
		}
	case 2:
		matchedFields = collectAllFields(layers, true)
	}

	// Deduplicate fields by name+value.
	seen := make(map[string]bool)
	var uniqueFields []FieldEntry
	for _, f := range matchedFields {
		key := f.Name + ":" + f.Value
		if !seen[key] {
			seen[key] = true
			uniqueFields = append(uniqueFields, f)
		}
	}

	// Filter out hidden fields (-hide-field).
	// Matches against "name: value" line, same as -show-field.
	if len(config.HideFields) > 0 {
		var filtered []FieldEntry
		for _, f := range uniqueFields {
			line := strings.ToLower(f.Name + ": " + f.Value)
			hide := false
			for _, pattern := range config.HideFields {
				if strings.Contains(line, strings.ToLower(pattern)) {
					hide = true
					break
				}
			}
			if !hide {
				filtered = append(filtered, f)
			}
		}
		uniqueFields = filtered
	}

	// In very quiet mode (-qq), suppress packets with no matched fields.
	if config.Quiet == 2 && len(uniqueFields) == 0 {
		return ""
	}

	// Build compare lookup if any template matches this packet.
	// Match against all fields from layers, not just displayed fields.
	var compareFields map[string]CompareField
	if config.CompareMode != "" && len(compareTemplates) > 0 {
		allFields := collectAllFields(layers, true)
		for _, tmpl := range compareTemplates {
			var matched bool
			switch config.CompareMode {
			case "frame":
				matched = matchesCompareFrame(protocolKey, allFields, tmpl)
			case "field":
				matched = matchesCompareField(allFields, tmpl)
			}
			if matched {
				compareFields = make(map[string]CompareField)
				for _, cf := range tmpl.Fields {
					if cf.Compare {
						compareFields[cf.Name] = cf
					}
				}

				if config.CompareMode == "frame" {
					// Frame mode: template fields replace default fields.
					// Reset uniqueFields and rebuild from template.
					uniqueFields = nil
					displayedNames := make(map[string]bool)

					// Add all template fields (starred and non-starred) from packet.
					templateFieldNames := make(map[string]bool)
					for _, tf := range tmpl.Fields {
						templateFieldNames[tf.Name] = true
					}
					for _, af := range allFields {
						if templateFieldNames[af.Name] && !displayedNames[af.Name] {
							uniqueFields = append(uniqueFields, af)
							displayedNames[af.Name] = true
						}
					}

					// With -v, add remaining app-layer fields.
					if config.Verbose >= 1 {
						appFields := collectAllFields(layers, false)
						for _, af := range appFields {
							if !displayedNames[af.Name] {
								uniqueFields = append(uniqueFields, af)
								displayedNames[af.Name] = true
							}
						}
					}
					// With -vv, also add transport/network fields.
					if config.Verbose >= 2 {
						for _, af := range allFields {
							if !displayedNames[af.Name] {
								uniqueFields = append(uniqueFields, af)
								displayedNames[af.Name] = true
							}
						}
					}
				} else {
					// Field mode: ensure compared fields are in display list.
					displayedNames := make(map[string]bool)
					for _, f := range uniqueFields {
						displayedNames[f.Name] = true
					}
					for _, af := range allFields {
						if _, isCompare := compareFields[af.Name]; isCompare && !displayedNames[af.Name] {
							uniqueFields = append(uniqueFields, af)
							displayedNames[af.Name] = true
						}
					}
				}
				break
			}
		}

		// In compare mode, suppress packets that don't match any template.
		if compareFields == nil {
			return ""
		}
	}
	output.WriteString(headerLine)

	// In compare field mode, only show compared (starred) fields.
	if compareFields != nil && config.CompareMode == "field" {
		var compareEntries []FieldEntry
		for _, f := range uniqueFields {
			if _, ok := compareFields[f.Name]; ok {
				compareEntries = append(compareEntries, f)
			}
		}
		uniqueFields = compareEntries
	}

	// Render field tree.
	fieldNameColor := color.RGB(180, 180, 180)
	yellowColor := color.New(color.FgYellow)
	greenColor := color.New(color.FgGreen)
	for i, f := range uniqueFields {
		prefix := "├─"
		if i == len(uniqueFields)-1 {
			prefix = "└─"
		}

		if cf, ok := compareFields[f.Name]; ok {
			// Compare field: show actual value, then │ template value.
			if f.Value == cf.Value {
				// Values match: actual value green, template value white.
				output.WriteString(fmt.Sprintf("  %s %s: %s %s %s\n",
					protocolColor.Sprint(prefix), fieldNameColor.Sprint(f.Name),
					greenColor.Sprint(f.Value), white.Sprint("│"), cf.Value))
			} else {
				// Values differ: actual value yellow, template value white.
				output.WriteString(fmt.Sprintf("  %s %s: %s %s %s\n",
					protocolColor.Sprint(prefix), fieldNameColor.Sprint(f.Name),
					yellowColor.Sprint(f.Value), white.Sprint("│"), cf.Value))
			}
		} else {
			output.WriteString(fmt.Sprintf("  %s %s: %s\n",
				protocolColor.Sprint(prefix), fieldNameColor.Sprint(f.Name), f.Value))
		}
	}

	return output.String()
}

// ---------------------------------------------------------------------------
// Protocol detection
// ---------------------------------------------------------------------------

// detectProtocol returns the key and display name of the highest-priority
// protocol layer present in the packet. It first checks explicitly defined
// application protocols, then falls back to any unrecognized layer name from
// tshark (e.g. rdp, sip, ftp), and finally falls back to transport-level
// protocols (tcp, tls, ssh).
func detectProtocol(layers map[string]interface{}) (string, string) {
	// Pass 1: check known application-level protocols (above transport).
	for _, proto := range protocolPriorities {
		if skipLayers[proto] {
			continue
		}
		if _, exists := layers[proto]; exists {
			return proto, proto
		}
	}

	// Pass 2: any layer not in skipLayers and not a known protocol.
	// This catches protocols tshark decodes but gshark doesn't define
	// (e.g. rdp, ftp, sip, etc.), using tshark's layer name directly.
	for layerName := range layers {
		if skipLayers[layerName] || strings.HasSuffix(layerName, "_raw") {
			continue
		}
		if _, isKnown := protocolColors[layerName]; isKnown {
			continue
		}
		return layerName, layerName
	}

	// Pass 3: fall back to transport-level known protocols (tcp, tls, ssh).
	for _, proto := range protocolPriorities {
		if !skipLayers[proto] {
			continue
		}
		if _, exists := layers[proto]; exists {
			return proto, proto
		}
	}

	return "unknown", "UNKNOWN"
}

// ---------------------------------------------------------------------------
// Field extraction
// ---------------------------------------------------------------------------

// extractField retrieves a single field value from the packet layers.
// The fieldPath is a dot-separated string like "ip.src" where the first
// component is the layer name and the rest is the field name within that layer.
func extractField(layers map[string]interface{}, fieldPath string) string {
	parts := strings.SplitN(fieldPath, ".", 2)
	if len(parts) < 2 {
		return ""
	}

	layerData, exists := layers[parts[0]]
	if !exists {
		return ""
	}

	return findFieldValue(layerData, fieldPath)
}

// findFieldValue recursively searches nested JSON structures for a field
// matching the given name and returns its string representation.
func findFieldValue(data interface{}, fieldName string) string {
	switch v := data.(type) {
	case map[string]interface{}:
		if val, exists := v[fieldName]; exists {
			return valueToString(val)
		}
		for _, nested := range v {
			if result := findFieldValue(nested, fieldName); result != "" {
				return result
			}
		}
	case []interface{}:
		for _, item := range v {
			if result := findFieldValue(item, fieldName); result != "" {
				return result
			}
		}
	}
	return ""
}

// valueToString converts a JSON value to its string representation.
// Arrays with a single element are unwrapped. Multi-element arrays are
// joined with commas.
func valueToString(val interface{}) string {
	switch v := val.(type) {
	case string:
		return v
	case []interface{}:
		if len(v) == 1 {
			return valueToString(v[0])
		}
		var parts []string
		for _, item := range v {
			parts = append(parts, valueToString(item))
		}
		return strings.Join(parts, ", ")
	case map[string]interface{}:
		for _, nested := range v {
			if s, ok := nested.(string); ok {
				return s
			}
		}
	case float64:
		return fmt.Sprintf("%.0f", v)
	case bool:
		return fmt.Sprintf("%t", v)
	}
	return fmt.Sprintf("%v", val)
}

// ---------------------------------------------------------------------------
// Field collection
// ---------------------------------------------------------------------------

// walkLayers flattens all fields from sorted protocol layers, skipping _raw
// layers and optionally skipping transport layers. protocolKey allows the
// detected protocol's own layer through even if it's in skipLayers.
func walkLayers(layers map[string]interface{}, includeTransport bool, protocolKey string) []FieldEntry {
	var layerNames []string
	for name := range layers {
		layerNames = append(layerNames, name)
	}
	sortLayerNames(layerNames)

	var fields []FieldEntry
	for _, layerName := range layerNames {
		if strings.HasSuffix(layerName, "_raw") {
			continue
		}
		if !includeTransport && skipLayers[layerName] && layerName != protocolKey {
			continue
		}
		fields = append(fields, flattenLayer(layerName, layers[layerName])...)
	}
	return fields
}

// collectDefaultFields returns the protocol-specific fields defined in the
// protocol's Fields list. If NTLM auth is present alongside the primary
// protocol, those fields are included as well.
func collectDefaultFields(layers map[string]interface{}, protocolKey string) []FieldEntry {
	fieldPrefixes := defaultFields[protocolKey]
	if fieldPrefixes == nil {
		return nil
	}

	// Include NTLM fields if present alongside the primary protocol.
	if _, hasNTLM := layers["ntlmssp"]; hasNTLM && protocolKey != "ntlmssp" {
		fieldPrefixes = append(fieldPrefixes, defaultFields["ntlmssp"]...)
	}

	var fields []FieldEntry
	for _, f := range walkLayers(layers, false, protocolKey) {
		for _, prefix := range fieldPrefixes {
			if f.Name == prefix {
				fields = append(fields, f)
				break
			}
		}
	}
	return fields
}

// collectShowFields returns fields whose name, value, or full "name: value"
// line partially matches any of the user-supplied -show-field patterns
// (case-insensitive). This allows matching on field name ("dns.qry.name"),
// value ("TESTHOST"), or complete specification ("dns.qry.name: TESTHOST").
func collectShowFields(layers map[string]interface{}, showFields []string) []FieldEntry {
	var fields []FieldEntry
	for _, f := range walkLayers(layers, false, "") {
		line := strings.ToLower(f.Name + ": " + f.Value)
		for _, show := range showFields {
			if strings.Contains(line, strings.ToLower(show)) {
				fields = append(fields, f)
				break
			}
		}
	}
	return fields
}

// collectAllFields returns all fields from every layer. If includeTransport is
// false, transport/network layers (frame, eth, ip, tcp, udp) are skipped.
func collectAllFields(layers map[string]interface{}, includeTransport bool) []FieldEntry {
	return walkLayers(layers, includeTransport, "")
}

// ---------------------------------------------------------------------------
// Layer flattening
// ---------------------------------------------------------------------------

// flattenLayer recursively walks a JSON layer structure and produces a flat
// list of FieldEntry values. Nested objects are recursed into; _tree suffixed
// keys and empty strings are skipped.
func flattenLayer(parentKey string, data interface{}) []FieldEntry {
	var fields []FieldEntry

	switch v := data.(type) {
	case map[string]interface{}:
		var keys []string
		for k := range v {
			keys = append(keys, k)
		}
		sort.Strings(keys)

		for _, key := range keys {
			val := v[key]
			switch nested := val.(type) {
			case string:
				trimmed := strings.TrimSpace(nested)
				if !strings.HasSuffix(key, "_tree") && trimmed != "" {
					fields = append(fields, FieldEntry{Name: key, Value: trimmed})
				}
			case []interface{}:
				if strVal := valueToString(nested); strVal != "" && !strings.HasSuffix(key, "_tree") {
					fields = append(fields, FieldEntry{Name: key, Value: strVal})
				}
			case map[string]interface{}:
				fields = append(fields, flattenLayer(key, nested)...)
			case float64:
				fields = append(fields, FieldEntry{Name: key, Value: fmt.Sprintf("%.0f", nested)})
			case bool:
				fields = append(fields, FieldEntry{Name: key, Value: fmt.Sprintf("%t", nested)})
			}
		}
	case []interface{}:
		for _, item := range v {
			fields = append(fields, flattenLayer(parentKey, item)...)
		}
	case string:
		if trimmed := strings.TrimSpace(v); trimmed != "" {
			fields = append(fields, FieldEntry{Name: parentKey, Value: trimmed})
		}
	}

	return fields
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// sortLayerNames sorts layer names by protocol stack position (lowest layer
// first). Unknown layers are placed at defaultProtocolOrder. Ties are broken
// alphabetically.
func sortLayerNames(names []string) {
	sort.Slice(names, func(i, j int) bool {
		oi, oki := layerDisplayOrder[names[i]]
		oj, okj := layerDisplayOrder[names[j]]
		if !oki {
			oi = defaultProtocolOrder
		}
		if !okj {
			oj = defaultProtocolOrder
		}
		if oi != oj {
			return oi < oj
		}
		return names[i] < names[j]
	})
}

// ansiRegex matches ANSI escape sequences (color codes).
var ansiRegex = regexp.MustCompile(`\033\[[0-9;]*m`)

// stripAnsiCodes removes ANSI escape sequences from a string. Used to produce
// clean log file output from colorized terminal output.
func stripAnsiCodes(str string) string {
	return ansiRegex.ReplaceAllString(str, "")
}

// ---------------------------------------------------------------------------
// Compare template
// ---------------------------------------------------------------------------

// parseCompareFile reads a gshark output file and parses it into one or more
// CompareTemplates. Each header line ([PROTOCOL] ...) starts a new template.
// Fields ending with * are marked for value comparison.
func parseCompareFile(path string) ([]*CompareTemplate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	content := string(data)
	// Strip UTF-8 BOM if present.
	content = strings.TrimPrefix(content, "\xEF\xBB\xBF")
	lines := strings.Split(content, "\n")
	var templates []*CompareTemplate
	var current *CompareTemplate

	for _, line := range lines {
		line = strings.TrimRight(line, "\r")
		clean := ansiRegex.ReplaceAllString(line, "")
		trimmed := strings.TrimSpace(clean)

		// Check if this is a header line: [PROTOCOL] [...]
		if strings.HasPrefix(trimmed, "[") && !strings.HasPrefix(trimmed, "├─") && !strings.HasPrefix(trimmed, "└─") {
			if idx := strings.Index(trimmed, "["); idx >= 0 {
				if end := strings.Index(trimmed[idx+1:], "]"); end >= 0 {
					// Save previous template if it has fields.
					if current != nil && len(current.Fields) > 0 {
						templates = append(templates, current)
					}
					current = &CompareTemplate{
						Protocol: strings.ToLower(strings.TrimSpace(trimmed[idx+1 : idx+1+end])),
					}
					continue
				}
			}
		}

		// Parse field lines: "  ├─ field.name: value" or "  └─ field.name: value"
		if !strings.HasPrefix(trimmed, "├─") && !strings.HasPrefix(trimmed, "└─") {
			continue
		}
		if current == nil {
			continue
		}

		// Remove tree prefix.
		fieldPart := trimmed
		for _, prefix := range []string{"├─ ", "└─ ", "├─", "└─"} {
			if strings.HasPrefix(fieldPart, prefix) {
				fieldPart = strings.TrimPrefix(fieldPart, prefix)
				break
			}
		}
		fieldPart = strings.TrimSpace(fieldPart)

		// Split on first ": " to get name and value.
		sepIdx := strings.Index(fieldPart, ": ")
		if sepIdx < 0 {
			continue
		}
		name := fieldPart[:sepIdx]
		value := fieldPart[sepIdx+2:]

		cf := CompareField{Name: name}
		if strings.HasSuffix(value, "**") {
			cf.Compare = true
			cf.ExactMatch = true
			cf.Value = strings.TrimSuffix(value, "**")
		} else if strings.HasSuffix(value, "*") {
			cf.Compare = true
			cf.Value = strings.TrimSuffix(value, "*")
		} else {
			cf.Value = value
		}
		current.Fields = append(current.Fields, cf)
	}

	// Don't forget the last template.
	if current != nil && len(current.Fields) > 0 {
		templates = append(templates, current)
	}

	if len(templates) == 0 {
		return nil, fmt.Errorf("no valid templates found in compare file")
	}

	return templates, nil
}

// matchesCompareField checks if a packet contains at least one starred field
// from the template. Ignores protocol. For ** fields, the value must also
// match exactly. Returns true if at least one starred field matches.
func matchesCompareField(fields []FieldEntry, tmpl *CompareTemplate) bool {
	have := make(map[string]string) // name -> value
	for _, f := range fields {
		have[f.Name] = f.Value
	}
	for _, tf := range tmpl.Fields {
		if !tf.Compare {
			continue
		}
		val, present := have[tf.Name]
		if !present {
			continue
		}
		if tf.ExactMatch && val != tf.Value {
			continue
		}
		return true
	}
	return false
}

// matchesCompareFrame checks if a packet matches a template by protocol and
// field presence. Protocol must match (case-insensitive). ALL starred fields
// must be present. For ** fields, the value must also match exactly.
func matchesCompareFrame(proto string, fields []FieldEntry, tmpl *CompareTemplate) bool {
	if !strings.EqualFold(proto, tmpl.Protocol) {
		return false
	}
	have := make(map[string]string) // name -> value
	for _, f := range fields {
		have[f.Name] = f.Value
	}
	for _, tf := range tmpl.Fields {
		if !tf.Compare {
			continue
		}
		val, present := have[tf.Name]
		if !present {
			return false
		}
		if tf.ExactMatch && val != tf.Value {
			return false
		}
	}
	return true
}
