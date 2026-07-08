# Prerequisites
requires tshark to be installed

# Usage
```
Usage: gshark [options]

Input:
  -i string           Network interface to capture on (default "eth0")
  -pcap string        PCAP file to read from instead of live capture
  -tshark string      Path to tshark executable

Output:
  -Y string           Wireshark display filter (default "frame")
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
  -v                  Display all fields including transport/network layers (frame/eth/ip/tcp/udp)
                      (default already shows all application-layer fields)

Compare:
  -compare-frame string  Template: match by protocol + all starred fields, show all fields
  -compare-field string  Template: match and diff only starred fields across all protocols
                         Use * to diff a field, ** to require exact value match

Decryption:
  -ntlm-pass string   NTLM password for decrypting sealed sessions (limited support)
```
