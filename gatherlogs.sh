#!/bin/bash

#hopefully this script can gather all the logs i want:  bro, snippets from scripts/runbro.sh
#,headers from justniffer,do suricata ids shit

sim=$1
user=elcabezon

run_bro() {
  bro -Cr $sim local > /dev/null 2>&1
  if [ -f http.log ]; then
  bro-cut id.resp_h < http.log | sort -u >> ips.list.log
fi
}

who() {
  cat ips.list |  nc whois.cymru.com 43 | grep -v '#' | egrep -v '^AS' >> whois.log
  rm ips.list.log
}

snippets() {
echo -e "-----top-bytes-exchanged--------\n"
if [ -f conn.log ]; then
  bro-cut -d uid ts id.orig_h id.orig_p id.resp_h id.resp_p service duration orig_bytes resp_bytes < conn.log | sort -nrk10 | head -n10
fi
echo -e "----------------------------\n"

echo -e "----top http requests------\n"
if [ -f http.log ]; then
  bro-cut host id.resp_h < http.log | sort | uniq -c | sort -nr | head -n10
fi
echo -e "----top http requests-----\n" 

echo -e "----top dns A requests--------\n"
if [ -f dns.log ]; then
  bro-cut query qtype_name < dns.log | awk '$2 ~/^A$/ {print $1}' | sort | uniq -c | sort -nr | head -n10
fi
echo -e "-----dns  A requests--------\n"


echo -e "-----top service/ports--------\n"
if [ -f conn.log ]; then
  bro-cut service id.resp_p < conn.log | sort | uniq -c | sort -nr | head -n10
fi
echo -e "-----top service/ports--------\n"


echo -e "-----top ssl servers--------\n"
if [ -f ssl.log ]; then
  bro-cut server_name < ssl.log | sort | uniq -c | sort -nr | head -n10
fi
echo -e "-----ssl servers-------\n"

}

sniffing() {
  ~/bin/./sniffing_just_http.sh $sim >> headers.log
}

suri() {
  if [ -f /var/log/suricata/stats.log ];
  then
  sudo rm -r /var/log/suricata/*
  fi
  ~/bin/./runsuricata.sh $sim > /dev/null 2>&1
}


move_suricata_rules() {
   du  /var/log/suricata/fast.log | egrep -o '[0-9]' | while read r; do if [[ "$r" -gt 0 ]]; then
  sudo cp /var/log/suricata/fast.log $PWD
  sudo chown "$user":"$user" fast.log
fi
done
}

latched_rules() {
if [ -f fast.log ]; then
egrep -o '\[[0-9]:[0-9]{7}:[0-9]\]' fast.log | awk -F: '{print $2}' | sort -u | while read r; 
do grep "$r" /usr/local/etc/suricata/rules/*rules >> matched_rules.log 2>&1; done
cat matched_rules.log | grep -v 'Permission denied' | grep -o 'alert.*' >> rules_matched.log
rm matched_rules.log
else
  echo "no suri rules for you"
fi
}

echo "gathering logs"
run_bro
snippets >> snippets.log
sniffing
suri
move_suricata_rules
latched_rules
#matched_rules
