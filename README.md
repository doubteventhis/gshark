# Prerequisites
requires tshark to be installed

# Help
```
Usage: gshark [options]

Input:
  -i string           Network interface to capture on (default "eth0")
  -pcap string        PCAP file to read from instead of live capture
  -tshark string      Path to tshark executable

Output:
  -Y string           Wireshark display filter (default "frame")
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
```

# Examples
### view ntlm traffic during HTTP -> LDAP relay:
`$ sudo ./gshark -Y 'not arp and not ssh' -hide-transport -q --show-field 'ntlmssp.messagetype,ntlmserverchallenge,ntproofstr,channel_bindings,target_name,dns_domain_name' -o relay.txt`  
<img width="852" height="634" alt="image" src="https://github.com/user-attachments/assets/2696a847-6530-4734-ba1b-fbe2ad9c9766" />


