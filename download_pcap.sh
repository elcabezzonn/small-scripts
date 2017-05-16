#!/bin/bash
#usually use this in combination with another_pcap_dir.sh. I use this typically to grab pcaps from the awesome malwaretraffic
#analysis, broadanalysis and all those other great sites that share their pcaps to the community. 

wget $1 && unzip -P infected ${1##*/}

