find . -maxdepth 1 -type f -regex '.*\.pcap\(ng\)?' -print0 | xargs -0 -l /bin/bash -c 'mkdir "${1%.*}"; /bin/bash /home/elcabezon/bin/./shatherlogs.sh "$1"  && mv "$1" *log extract_files "${1%.*}"' /bin/bash

