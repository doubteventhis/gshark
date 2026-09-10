gshark is a command-line wrapper around tshark that prints colorized, tree-formatted output. It uses wireshark's display filters and supports live traffic or reading from a pcap file. There is a compare mode that diffs captures against a saved template to easily spot differences. 

# Prerequisites
requires tshark to be installed

# Help
```
$ ./gshark -h                                                     
Usage: gshark [options]

Input:
  -i string           Network interface to capture on (default "eth0")
  -pcap string        PCAP file to read from instead of live capture
  -tshark string      Path to tshark executable

Output:
  -no-color           Disable colored output
  -no-banner          Suppress the gshark banner

  -Y string           Wireshark display filter (default "frame", matches everything)
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
```

# Examples
### View ntlm traffic during HTTP -> LDAP relay:
`$ sudo ./gshark -Y 'not arp and not ssh' -hide-transport -q --show-field 'ntlmssp.messagetype,ntlmserverchallenge,ntproofstr,channel_bindings,target_name,dns_domain_name' -o relay.txt`  
<img width="852" height="634" alt="image" src="https://github.com/user-attachments/assets/2696a847-6530-4734-ba1b-fbe2ad9c9766" />
  
### View multicast dns traffic emitted during lookups
`$ sudo ./gshark -Y 'not arp and not ssh' -hide-transport -q`
<img width="625" height="383" alt="image" src="https://github.com/user-attachments/assets/14c1a9f6-86f3-42b5-9ae7-58a4da9dd3b6" />


### Compare ntlmssp auth between a windows computer client and impacket
capture the windows client auth:
`> .\gshark-windows-amd64.exe -Y "smb or smb2" -o smb_ntmlssp_capture.txt`
<img width="885" height="307" alt="image" src="https://github.com/user-attachments/assets/1a766b89-19f6-4ce1-80a7-432040aab2eb" />


create a template to match against (the ntlm auth exchange):
```
[SMB2] [10.2.10.32:52246 -> 10.2.10.12:445] [2026-09-10 13:07:42.474] [Stream: 7]
<SNIP>
  ├─ **ntlmssp.messagetype: 0x00000001
<SNIP>
[SMB2] [10.2.10.12:445 -> 10.2.10.32:52246] [2026-09-10 13:07:42.474] [Stream: 7]
<SNIP>
  ├─ **ntlmssp.messagetype: 0x00000002
<SNIP>
[SMB2] [10.2.10.32:52246 -> 10.2.10.12:445] [2026-09-10 13:07:42.475] [Stream: 7]
<SNIP>
  ├─ **ntlmssp.messagetype: 0x00000003
<SNIP>
```

use compare to check the difference between the windows template and a recorded impacket smb authentication:  
`$ sudo ./gshark -compare-frame smb/templates/smb_ntmlssp_capture.txt -pcap smb/impacket_smb.pcap -hide-matches`
<img width="848" height="407" alt="image" src="https://github.com/user-attachments/assets/9c839343-49a3-4596-9df1-ba036de2c3f0" />


###
