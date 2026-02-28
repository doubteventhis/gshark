# Prerequisites
gshark uses wireshark's network dissectors and requires `tshark` (Wireshark CLI) to be installed

# Usage
```
Usage: gshark [options]

Input:
  -i string           Network interface to capture on (default "eth0")
  -pcap string        PCAP file to read from instead of live capture
  -tshark string      Path to tshark executable

Output:
  -Y string           Wireshark display filter (default "frame")
  -hide-tcp-nego      Hide transport-only packets (TCP handshakes, ACKs, etc.)

  -w string           Write raw pcap output to file
  -o string           Write gshark output to log file

  -no-color           Disable colored output
  -no-banner          Suppress the gshark banner

Verbosity:
  -show-field string  Additional fields to display (comma separated, partial match)
  -qq                 Very quiet mode: only display packets with matched fields
  -q                  Quiet mode: only display protocol headers
  -v                  Display all fields for application layer protocols
  -vv                 Display all fields including transport/network layers

Compare:
  -compare string     Template file for field comparison (fields ending with * are diffed)

Decryption:
  -ntlm-pass string   NTLM password for decrypting sealed sessions (limited support)
```

# Examples
```bash
# Live capture
sudo gshark -i eth0

# Live capture with a custom display filter
sudo gshark -Y "http or dns"

# Read from pcap
gshark -pcap capture.pcap
```

### Verbosity levels

```bash
# Default: built in protocol specific fields
gshark -pcap capture.pcap

# Quiet: protocol headers lines only
gshark -pcap capture.pcap -q

# Very quiet: only show packets matching -show-field. -show-field matches partial strings in feild names and values.
gshark -pcap capture.pcap -qq -show-field ntlmssp.auth.username

# Verbose: all application layer fields
gshark -pcap capture.pcap -v

# Very verbose: all fields including transport/network layers
gshark -pcap capture.pcap -vv
```

### Output to files
```bash
# Write parsed output to a log file
sudo gshark -o capture.log

# Write raw pcap for later analysis
sudo gshark -w capture.pcap

# Both at once
sudo gshark -w raw.pcap -o parsed.log
```

# Compare mode

Compare live traffic or pcap against a template to detect field value changes. Create a template by saving gshark output and adding `*` to fields you want to diff:

**Template file** (`baseline.txt`):
```


```

- Fields without `*` are used for **matching** (field name must exist in the packet)
- Fields with `*` are used for **comparison** (values are diffed against live traffic)
- Multiple packet templates can be defined in a single file

**Run:**
```bash

```

**Output when a value differs:**
```

```

The actual value (`304`) is shown in yellow when it differs from the template, with the template value (`200`) shown after `│` in white. Matching values are shown in green.


# How It Works

1. Spawns `tshark` with JSON output (`-T json`)
2. Streams and decodes packets from tshark's JSON array output]
3. Extracts and formats fields based on the selected verbosity level
4. Outputs color-coded, tree-formatted results to the terminal
