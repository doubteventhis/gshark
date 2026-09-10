package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"regexp"
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
	{Key: "icmp", Color: color.RGB(255, 100, 200)},
	{Key: "icmpv6", Color: color.RGB(255, 100, 200)},
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

// set link/network/transport layers excluded from output unless -v is used
var skipLayers = map[string]bool{
	"frame": true, "frame_raw": true,
	"eth": true, "eth_raw": true,
	"vlan": true, "vlan_raw": true, "ieee8021ad": true, "ieee8021ad_raw": true,
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
		"--no-duplicate-keys",
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

	// run tshark
	cmd := exec.Command(tsharkCmd, tsharkArgs...)

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

	// on SIGINT/SIGTERM, kill tshark
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigChan
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

	// report template frames that never appeared (compare-frame mode)
	printAbsentCompareFrames()

	if err := cmd.Wait(); err != nil {

		// suppress the "signal: killed" error from our own signal handler
		if cmd.ProcessState != nil && cmd.ProcessState.ExitCode() == -1 {
			return
		}
		fmt.Fprintf(os.Stderr, "[!] tshark exited with error: %v\n", err)
		os.Exit(1)
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
			// tshark closed its output (end of the pcap, or killed by our signal handler)
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
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
	protocolKey, protocolName := detectProtocol(layers, order)

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

	// build vlan string
	var vlanStr string
	vlanIDs := append(collectFieldValues(layers["ieee8021ad"], "ieee8021ad.id"), collectFieldValues(layers["vlan"], "vlan.id")...)
	if len(vlanIDs) > 0 {
		vlanStr = fmt.Sprintf(" %s%s%s", white.Sprint("["), grey.Sprintf("VLAN %s", strings.Join(vlanIDs, "/")), white.Sprint("]"))
	}

	var timestampStr string
	if timestamp != "" {
		timestampStr = fmt.Sprintf(" %s%s%s", white.Sprint("["), grey.Sprint(timestamp), white.Sprint("]"))
	}

	headerLine := fmt.Sprintf("%s%s%s %s%s %s %s%s%s%s%s\n",
		white.Sprint("["), protocolColor.Sprint(strings.ToUpper(protocolName)), white.Sprint("]"),
		white.Sprint("["), white.Sprint(srcEndpoint), white.Sprint("->"), white.Sprint(dstEndpoint), white.Sprint("]"),
		vlanStr, timestampStr, transport)

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

	// compare against template(s). frame mode aligns each packet to a template block and
	// prints a full-frame diff; field mode augments the display list with compared fields.
	var compareFields map[string]CompareField
	if config.CompareMode != "" && len(compareTemplates) > 0 {
		allFields := collectAllFields(layers, order, true)

		// frame mode: align to the best-matching template block, then diff the whole frame.
		// ** fields are alignment keys (must be present and equal); every other field is
		// diffed automatically and is never a match requirement. among eligible blocks the
		// one sharing the most field names with the packet wins.
		if config.CompareMode == "frame" {
			fvals, frameOrder := fieldValueMap(allFields)
			var best *CompareTemplate
			bestScore := 0
			for _, tmpl := range compareTemplates {
				if ok, score := alignCompareFrame(protocolKey, fvals, tmpl); ok && score > bestScore {
					best, bestScore = tmpl, score
				}
			}
			// no template block aligned: suppress the frame entirely
			if best == nil {
				return ""
			}
			compareFrameHits[best] = true
			showTransport := config.Verbose >= 1 || templateHasTransport(best)
			return headerLine + renderFrameDiff(protocolColor, best, fvals, frameOrder, showTransport)
		}

		// field mode: augment the display list with compared fields present in the packet
		for _, tmpl := range compareTemplates {
			if !matchesCompareField(allFields, tmpl) {
				continue
			}
			compareFields = make(map[string]CompareField)
			for _, cf := range tmpl.Fields {
				if cf.Compare {
					compareFields[cf.Name] = cf
				}
			}
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
			break
		}

		// suppress packets that don't match any template.
		if compareFields == nil {
			return ""
		}
	}
	output.WriteString(headerLine)

	// compare-field mode, only show compared fields (with -hide-matches, drop the ones that match)
	if compareFields != nil && config.CompareMode == "field" {
		var compareEntries []FieldEntry
		for _, f := range uniqueFields {
			cf, ok := compareFields[f.Name]
			if !ok {
				continue
			}
			if config.HideMatches && f.Value == cf.Value {
				continue
			}
			compareEntries = append(compareEntries, f)
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

// compareFrameHits records which template blocks matched at least one packet, so
// printAbsentCompareFrames can report template frames that never appeared in the capture.
var compareFrameHits = map[*CompareTemplate]bool{}

// fieldValueMap groups field entries by name into a value multiset and records first-seen order.
func fieldValueMap(fields []FieldEntry) (map[string][]string, []string) {
	m := make(map[string][]string)
	var order []string
	for _, f := range fields {
		if _, ok := m[f.Name]; !ok {
			order = append(order, f.Name)
		}
		m[f.Name] = append(m[f.Name], f.Value)
	}
	return m, order
}

// multisetEqual reports whether two value slices hold the same values regardless of order.
func multisetEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	ac := append([]string(nil), a...)
	bc := append([]string(nil), b...)
	sort.Strings(ac)
	sort.Strings(bc)
	for i := range ac {
		if ac[i] != bc[i] {
			return false
		}
	}
	return true
}

// isSkipLayerField reports whether a field belongs to a link/network/transport layer.
func isSkipLayerField(name string) bool {
	if i := strings.IndexByte(name, '.'); i > 0 {
		return skipLayers[name[:i]]
	}
	return skipLayers[name]
}

// prints a diff of a captured frame against a template
func renderFrameDiff(protocolColor *color.Color, tmpl *CompareTemplate, fvals map[string][]string, frameOrder []string, showTransport bool) string {
	yellow := color.New(color.FgYellow)
	green := color.New(color.FgGreen)
	red := color.New(color.FgRed)
	gray := color.RGB(180, 180, 180)
	dim := color.New(color.FgHiBlack)
	white := color.New(color.FgHiWhite, color.Bold)

	// template values and first-seen order
	tvals := make(map[string][]string)
	var torder []string
	for _, tf := range tmpl.Fields {
		if _, ok := tvals[tf.Name]; !ok {
			torder = append(torder, tf.Name)
		}
		tvals[tf.Name] = append(tvals[tf.Name], tf.Value)
	}

	// union of names: template order first, then capture-only names in capture order
	var names []string
	seen := make(map[string]bool)
	for _, n := range torder {
		if !seen[n] {
			names = append(names, n)
			seen[n] = true
		}
	}
	for _, n := range frameOrder {
		if seen[n] || (!showTransport && isSkipLayerField(n)) {
			continue
		}
		names = append(names, n)
		seen[n] = true
	}

	type piece struct {
		name string
		body string
	}
	var pieces []piece
	for _, n := range names {
		tv, inT := tvals[n]
		fv, inF := fvals[n]
		var body string
		switch {
		case inT && inF:
			if multisetEqual(tv, fv) {
				if config.HideMatches {
					continue
				}
				body = fmt.Sprintf("%s %s %s", green.Sprint(strings.Join(fv, ", ")), white.Sprint("│"), strings.Join(tv, ", "))
			} else {
				body = fmt.Sprintf("%s %s %s", yellow.Sprint(strings.Join(fv, ", ")), white.Sprint("│"), strings.Join(tv, ", "))
			}
		case inT && !inF:
			body = fmt.Sprintf("%s %s %s", red.Sprint("(absent)"), white.Sprint("│"), strings.Join(tv, ", "))
		case !inT && inF:
			// capture-only field: not defined in the template, so nothing to match. shown plain
			body = strings.Join(fv, ", ")
		}
		pieces = append(pieces, piece{n, body})
	}

	if len(pieces) == 0 {
		return "  " + protocolColor.Sprint("└─") + " " + dim.Sprint("(no differences)") + "\n"
	}

	var b strings.Builder
	for i, p := range pieces {
		prefix := "├─"
		if i == len(pieces)-1 {
			prefix = "└─"
		}
		b.WriteString(fmt.Sprintf("  %s %s: %s\n", protocolColor.Sprint(prefix), gray.Sprint(p.name), p.body))
	}
	return b.String()
}

// printAbsentCompareFrames reports template frames (frame mode) that never matched a packet.
func printAbsentCompareFrames() {
	if config.CompareMode != "frame" {
		return
	}
	var missing []*CompareTemplate
	for _, t := range compareTemplates {
		if !compareFrameHits[t] {
			missing = append(missing, t)
		}
	}
	if len(missing) == 0 {
		return
	}
	fmt.Printf("\n[!] %d template frame(s) had no match in the capture:\n", len(missing))
	for _, t := range missing {
		var keys []string
		for _, f := range t.Fields {
			if f.ExactMatch {
				keys = append(keys, f.Name+"="+f.Value)
			}
		}
		detail := ""
		if len(keys) > 0 {
			detail = " (" + strings.Join(keys, ", ") + ")"
		}
		fmt.Printf("    - [%s]%s\n", strings.ToUpper(t.Protocol), detail)
	}
}

// detects the protocol from the tshark input. order is tshark's layer order, bottom of the stack first
func detectProtocol(layers map[string]interface{}, order []string) (string, string) {

	// check for known application-level protocols
	for _, proto := range protocolPriorities {
		if skipLayers[proto] {
			continue
		}
		if _, exists := layers[proto]; exists {
			return proto, proto
		}
	}

	// any layer not in skipLayers and not a known protocol. catches undefined protocols
	hasData := false
	for i := len(order) - 1; i >= 0; i-- {
		layerName := order[i]
		if skipLayers[layerName] || strings.HasSuffix(layerName, "_raw") || strings.HasPrefix(layerName, "_ws.") {
			continue
		}
		if _, isKnown := protocolColors[layerName]; isKnown {
			continue
		}
		if layerName == "data" {
			hasData = true
			continue
		}
		return layerName, layerName
	}
	if hasData {
		return "data", "data"
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

// returns every value of fieldName found
func collectFieldValues(data interface{}, fieldName string) []string {
	var values []string
	switch v := data.(type) {
	case map[string]interface{}:
		if val, ok := v[fieldName]; ok {
			values = append(values, valueToString(val))
		}
	case []interface{}:
		for _, item := range v {
			values = append(values, collectFieldValues(item, fieldName)...)
		}
	}
	return values
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
		// iterate in sorted key order
		keys := make([]string, 0, len(v))
		for k := range v {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			if s, ok := v[k].(string); ok {
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
				var scalars []string
				for _, item := range nested {
					if obj, isObj := item.(map[string]interface{}); isObj {
						fields = append(fields, flattenLayer(key, obj)...)
					} else if s := strings.TrimSpace(valueToString(item)); s != "" {
						scalars = append(scalars, s)
					}
				}
				if len(scalars) > 0 && !strings.HasSuffix(key, "_tree") {
					fields = append(fields, FieldEntry{Name: key, Value: strings.Join(scalars, ", ")})
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
