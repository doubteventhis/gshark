package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/fatih/color"
)

type TSharkPacket struct {
	Source PacketSource `json:"_source"`
}

type PacketSource struct {
	Layers     map[string]interface{}
	LayerOrder []string
}

// decode tshark's json into PacketSource struct
func (ps *PacketSource) UnmarshalJSON(data []byte) error {
	var raw struct {
		Layers json.RawMessage `json:"layers"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	if len(raw.Layers) == 0 {
		return nil
	}
	if err := json.Unmarshal(raw.Layers, &ps.Layers); err != nil {
		return err
	}
	order, err := jsonObjectKeys(raw.Layers)
	if err != nil {
		return err
	}
	ps.LayerOrder = order
	return nil
}

// returns the keys of a JSON object in order
func jsonObjectKeys(data []byte) ([]string, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	tok, err := dec.Token()
	if err != nil {
		return nil, err
	}
	if delim, ok := tok.(json.Delim); !ok || delim != '{' {
		return nil, nil
	}
	var keys []string
	for dec.More() {
		keyTok, err := dec.Token()
		if err != nil {
			return nil, err
		}
		key, ok := keyTok.(string)
		if !ok {
			return nil, fmt.Errorf("unexpected non-string key in layers object")
		}
		keys = append(keys, key)
		var skip json.RawMessage
		if err := dec.Decode(&skip); err != nil {
			return nil, err
		}
	}
	return keys, nil
}

// defines a supported protocol
type ProtocolDef struct {
	Key   string
	Color *color.Color
}

// a single name-value pair extracted from a packet layer
type FieldEntry struct {
	Name  string
	Value string
}

// per protocol colors, add new protocols here
var protocols = []ProtocolDef{
	{Key: "ntlmssp", Color: color.New(color.FgHiRed)},
	{Key: "kerberos", Color: color.New(color.FgMagenta)},
	{Key: "smb2", Color: color.New(color.FgRed)},
	{Key: "smb", Color: color.New(color.FgRed)},
	{Key: "ldap", Color: color.RGB(255, 140, 0)},
	{Key: "ldaps", Color: color.RGB(255, 140, 0)},
	{Key: "http", Color: color.New(color.FgCyan)},
	{Key: "dns", Color: color.RGB(65, 105, 225)},
	{Key: "llmnr", Color: color.RGB(100, 149, 237)},
	{Key: "nbns", Color: color.RGB(0, 191, 255)},
	{Key: "mdns", Color: color.RGB(135, 206, 250)},
	{Key: "dhcpv6", Color: color.New(color.FgGreen)},
	{Key: "dcerpc", Color: color.New(color.FgHiCyan)},
	{Key: "icmpv6", Color: color.RGB(255, 100, 200)},
	{Key: "arp", Color: color.New(color.FgYellow)},
	{Key: "ssdp", Color: color.New(color.FgHiYellow)},
	{Key: "modbus", Color: color.New(color.FgHiGreen)},
	{Key: "nmf", Color: color.New(color.FgHiMagenta)},
	{Key: "tls", Color: color.New(color.FgHiBlue)},
	{Key: "tcp", Color: color.New(color.FgWhite)},
}

var (
	protocolColors     map[string]*color.Color
	protocolPriorities []string
)

// lists transport/network layers excluded from output unless -v is used.
var skipLayers = map[string]bool{
	"frame": true, "frame_raw": true,
	"eth": true, "eth_raw": true,
	"ip": true, "ipv6": true, "ip_raw": true, "ipv6_raw": true,
	"tcp": true, "udp": true, "tcp_raw": true, "udp_raw": true,
}

func init() {
	protocolColors = make(map[string]*color.Color)

	for _, p := range protocols {
		protocolColors[p.Key] = p.Color
		protocolPriorities = append(protocolPriorities, p.Key)
	}
}


func main() {
	config = parseFlags()

	if config.NoColor {
		color.NoColor = true
	}

	if !config.NoBanner {
		printBanner()
	}

	printStartupInfo()

	// tshark args
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

	// ntlm decryption
	if config.NtlmPassword != "" {
		tsharkArgs = append(tsharkArgs, "-o", "ntlmssp.nt_password:"+config.NtlmPassword)
	}

	// start the log file
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

	tsharkCmd := findTshark(config.TsharkPath)

	// start a separate process for raw pcap capture if -w is set
	var pcapCmd *exec.Cmd
	var pcapLabel string
	if config.JSONOutput != "" && config.PcapFile == "" {

		// use tshark on windows to write the pcap
		if runtime.GOOS == "windows" {
			pcapCmd = exec.Command(tsharkCmd, "-i", config.Interface, "-w", config.JSONOutput)
			pcapLabel = "tshark-pcap"

		// use tcpdump on linux
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

	// run tshark
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.Command(tsharkCmd, tsharkArgs...)

	// linux uses stdbuf 
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

	// on SIGINT/SIGTERM, kill both tshark processes
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigChan

		// stop pcap writer gracefully
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

	// drain tshark stderr in the background
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

	// process packets until tshark exits
	processJSONOutput(bufio.NewReader(stdout), logFile)

	if err := cmd.Wait(); err != nil {

		// suppress the "signal: killed" error from our own signal handler
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


// parses tsharks JSON array output, calls formatter, and prints line to stdout/logfile
func processJSONOutput(stdout *bufio.Reader, logFile *os.File) {
	decoder := json.NewDecoder(stdout)

	// expect opening bracket of the JSON array
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
				break
			}
			fmt.Fprintf(os.Stderr, "[!] Error decoding packet: %v\n", err)
			continue
		}

		output := formatPacketJSON(packet)
		if output != "" {
			fmt.Print(output)

			if logFile != nil {
				if _, err := logFile.WriteString(stripAnsiCodes(output)); err != nil {
					fmt.Fprintf(os.Stderr, "[!] Error writing to log file: %v\n", err)
				}
			}
		}
	}
}

// formats incoming packets
func formatPacketJSON(packet TSharkPacket) string {
	var output strings.Builder
	layers := packet.Source.Layers
	order := packet.Source.LayerOrder

	// extract source and destination
	srcIP := extractField(layers, "ip.src")
	dstIP := extractField(layers, "ip.dst")

	// check ipv6
	if srcIP == "" {
		srcIP = extractField(layers, "ipv6.src")
		dstIP = extractField(layers, "ipv6.dst")
	}

	// fall back to mac if no ips
	if srcIP == "" {
		srcIP = extractField(layers, "eth.src")
		dstIP = extractField(layers, "eth.dst")
	}

	// pull ports and streams
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


	// find the protocol we're parsing
	protocolKey, protocolName := detectProtocol(layers)
	if config.HideTransport && skipLayers[protocolKey] {
		return ""
	}

	// check the assigned color or assign cyan
	protocolColor := protocolColors[protocolKey]
	if protocolColor == nil {
		protocolColor = color.New(color.FgCyan)
	}

	// build endpoint strings
	srcEndpoint := srcIP
	if srcPort != "" {
		srcEndpoint = srcIP + ":" + srcPort
	}
	dstEndpoint := dstIP
	if dstPort != "" {
		dstEndpoint = dstIP + ":" + dstPort
	}

	// extract timestamp
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

	// write protocol header line
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

	// collect fields based on verbosity level
	var matchedFields []FieldEntry

	switch config.Verbose {
	case 0:
		if config.Quiet == 0 {
			matchedFields = collectAllFields(layers, order, false)
		}
		if len(config.ShowFields) > 0 {
			matchedFields = append(matchedFields, collectShowFields(layers, order, config.ShowFields)...)
		}
	case 1:
		matchedFields = collectAllFields(layers, order, true)
	}

	// deduplicate fields by name+value
	seen := make(map[string]bool)
	var uniqueFields []FieldEntry
	for _, f := range matchedFields {
		key := f.Name + ":" + f.Value
		if !seen[key] {
			seen[key] = true
			uniqueFields = append(uniqueFields, f)
		}
	}

	// filter out hidden fields (-hide-field), matches on partials in field:value
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

	// in very quiet mode (-qq), suppress packets with no matched fields
	if config.Quiet == 2 && len(uniqueFields) == 0 {
		return ""
	}

	// build compare lookup if any template matches this packet, match against all fields from layers, not just displayed fields
	var compareFields map[string]CompareField
	if config.CompareMode != "" && len(compareTemplates) > 0 {
		allFields := collectAllFields(layers, order, true)
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

				// in compare-frame mode
				if config.CompareMode == "frame" {
					uniqueFields = nil
					displayedNames := make(map[string]bool)

					// add all template fields from packet
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

					// with -v, add all remaining fields
					if config.Verbose >= 1 {
						for _, af := range allFields {
							if !displayedNames[af.Name] {
								uniqueFields = append(uniqueFields, af)
								displayedNames[af.Name] = true
							}
						}
					}
				} else {
					// compare-fied mode, ensure compared fields are in display list
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

		// suppress packets that don't match any template.
		if compareFields == nil {
			return ""
		}
	}
	output.WriteString(headerLine)

	// compare-field mode, only show compared fields
	if compareFields != nil && config.CompareMode == "field" {
		var compareEntries []FieldEntry
		for _, f := range uniqueFields {
			if _, ok := compareFields[f.Name]; ok {
				compareEntries = append(compareEntries, f)
			}
		}
		uniqueFields = compareEntries
	}

	fieldNameColor := color.RGB(180, 180, 180)
	yellowColor := color.New(color.FgYellow)
	greenColor := color.New(color.FgGreen)
	for i, f := range uniqueFields {
		prefix := "├─"
		if i == len(uniqueFields)-1 {
			prefix = "└─"
		}

		if cf, ok := compareFields[f.Name]; ok {
			// compare-field, show actual value, then │ template value

			if f.Value == cf.Value {

				// values match: actual value green, template value white
				output.WriteString(fmt.Sprintf("  %s %s: %s %s %s\n",
					protocolColor.Sprint(prefix), fieldNameColor.Sprint(f.Name),
					greenColor.Sprint(f.Value), white.Sprint("│"), cf.Value))
			} else {

				// values dont match: actual value yellow, template value white.
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


// detects the protocol from the tshark input
func detectProtocol(layers map[string]interface{}) (string, string) {

	// check for known application-level protocols
	for _, proto := range protocolPriorities {
		if skipLayers[proto] {
			continue
		}
		if _, exists := layers[proto]; exists {
			return proto, proto
		}
	}

	// any layer not in skipLayers and not a known protocol. catches undefined protocols, uses tshark's name
	for layerName := range layers {
		if skipLayers[layerName] || strings.HasSuffix(layerName, "_raw") {
			continue
		}
		if _, isKnown := protocolColors[layerName]; isKnown {
			continue
		}
		return layerName, layerName
	}

	// fall back to transport-level known protocols (tcp, tls, ssh).
	for _, proto := range protocolPriorities {
		if !skipLayers[proto] {
			continue
		}
		if _, exists := layers[proto]; exists {
			return proto, proto
		}
	}

	// else print unknown
	return "unknown", "UNKNOWN"
}

// retrieves a single field value from the packet layers
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

// searches JSON for a field matching the given name
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

// converts a JSON value to its string 
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

// flattens fields from each layer in tshark's original order
func walkLayers(layers map[string]interface{}, order []string, includeTransport bool, protocolKey string) []FieldEntry {
	var fields []FieldEntry
	seen := make(map[string]bool)
	for _, layerName := range order {
		if seen[layerName] {
			continue
		}
		seen[layerName] = true
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

// returns fields that match -show-field 
func collectShowFields(layers map[string]interface{}, order []string, showFields []string) []FieldEntry {
	var fields []FieldEntry
	for _, f := range walkLayers(layers, order, false, "") {
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

// returns all fields from every layer. 
func collectAllFields(layers map[string]interface{}, order []string, includeTransport bool) []FieldEntry {
	return walkLayers(layers, order, includeTransport, "")
}

// returns a flat list of FieldEntry values
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

// ansiRegex matches ANSI escape sequences (colors)
var ansiRegex = regexp.MustCompile(`\033\[[0-9;]*m`)

// removes ANSI escape sequences (colors) from a string
func stripAnsiCodes(str string) string {
	return ansiRegex.ReplaceAllString(str, "")
}
