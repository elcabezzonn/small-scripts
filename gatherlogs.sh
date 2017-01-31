#!/bin/bash

#hopefully this script can gather all the logs i want:  bro, snippets from scripts/runbro.sh
#,headers from justniffer,do suricata ids shit

sim=$1


run_bro() {
  bro -Cr $sim local > /dev/null 2>&1
  bro-cut id.resp_h < http.log | sort -u >> ips.list
}

who() {
  cat ips.list |  nc whois.cymru.com 43 | grep -v '#' | egrep -v '^AS' >> ip.txt
  rm ips.list
}

snippets() {
  ~/scripts/./runbro.sh $sim >> snippets.log
}

sniffing() {
  ~/bin/./sniffing_just_http.sh >> headers.log
}

suri() {
  if [ -f /var/log/suricata/stats.log ];
  then
  sudo rm /var/log/suricata/*log
  fi
  ~/bin/./runsuricata.sh $sim > /dev/null 2>&1
}
echo "gathering logs"
run_bro
echo "whois"
who
echo "gathering snippets"
snippets
#sniffing
echo "suricata"
suri
