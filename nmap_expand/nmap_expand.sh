#!/bin/bash
# working with stuff from ~line 1804 in discover.sh to get fancy nmap stuff from already run scans

name=$1
echo $name

# first, this only works with files named nmap.nmap in discover.sh, so there's your first problem
egrep -v '(0000:|0010:|0020:|0030:|0040:|0050:|0060:|0070:|0080:|0090:|00a0:|00b0:|00c0:|00d0:|1 hop|closed|guesses|GUESSING|filtered|fingerprint|FINGERPRINT|general purpose|initiated|latency|Network Distance|No exact OS|No OS matches|OS:|OS CPE|Please report|RTTVAR|scanned in|SF|unreachable|Warning|WARNING)' $name.nmap | sed 's/Nmap scan report for //' | sed '/^$/! b end; n; /^$/d; : end' > $name.txt
#grep -o '[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}' $name.nmap | $sip > $name.txt
#hosts=$(wc -l $name/hosts.txt | cut -d ' ' -f1)

grep 'open' $name.txt | grep -v 'WARNING' | awk '{print $1}' | sort -un > ports.txt
grep 'tcp' ports.txt | cut -d '/' -f1 > ports-tcp.txt
grep 'udp' ports.txt | cut -d '/' -f1 > ports-udp.txt

grep 'open' $name.txt | grep -v 'really open' | awk '{for (i=4;i<=NF;i++) {printf "%s%s",sep, $i;sep=" "}; printf "\n"}' | sed 's/^ //' | sort -u | sed '/^$/d' > banners.txt

for i in $(cat ports-tcp.txt); do
     TCPPORT=$i
     cat $name.gnmap | grep " $i/open/tcp//http/\| $i/open/tcp//http-alt/\| $i/open/tcp//http-proxy/\| $i/open/tcp//appserv-http/" |
     sed -e 's/Host: //g' -e 's/ (.*//g' -e 's.^.http://.g' -e "s/$/:$i/g" | $sip >> tmp

#      cat $name.gnmap | grep " $i/open/tcp//https/\| $i/open/tcp//https-alt/\| $i/open/tcp//ssl|giop/\| $i/open/tcp//ssl|http/\| $i/open/tcp//ssl|unknown/" |
#      sed -e 's/Host: //g' -e 's/ (.*//g' -e 's.^.https://.g' -e "s/$/:$i/g" | $sip >> tmp2
done

# sed 's/http:\/\///g' tmp > http.txt
# sed 's/https:\/\///g' tmp2 > https.txt

# Remove all empty files
find . -type f -empty -exec rm {} +
