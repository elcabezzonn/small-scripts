#!/bin/bash
#this is a script to do protocol state machine with bro. I got this information from Liam Randall when he was instructing a class on bro at 
#bsides. It has helped me when looking for fields in bro when you are trying to script things 

#this allows you to pass I think unlimited commands to the script
filter=$@

usage() {
  echo "usage: $0"
  echo "provide a bpf filter argument to the script so it can dump it into a dump.log for protocol state machine"
  exit 1
}

if [[ $# -lt 1 ]]; then
  usage 
fi

#switch -e allows for tab completion 
read -ep "pcap plz : " pcap
bro -C -r "$pcap" policy/misc/dump-events.bro  "PacketFilter::default_capture_filter = \"""$filter""\"" local >> dump.log
 
