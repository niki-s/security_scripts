#!/bin/bash
# working with stuff from ~line 1804 in discover.sh to get fancy nmap stuff from already run scans

name="bora_fast_tcp"
echo $name

# first, this only works with files named nmap.nmap in discover.sh, so there's your first problem
egrep -v '(0000:|0010:|0020:|0030:|0040:|0050:|0060:|0070:|0080:|0090:|00a0:|00b0:|00c0:|00d0:|1 hop|closed|guesses|GUESSING|filtered|fingerprint|FINGERPRINT|general purpose|initiated|latency|Network Distance|No exact OS|No OS matches|OS:|OS CPE|Please report|RTTVAR|scanned in|SF|unreachable|Warning|WARNING)' $name.nmap | sed 's/Nmap scan report for //' | sed '/^$/! b end; n; /^$/d; : end' > $name.txt
#grep -o '[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}' $name.nmap | $sip > $name.txt
#hosts=$(wc -l $name/hosts.txt | cut -d ' ' -f1)

grep 'open' $name.txt | grep -v 'WARNING' | awk '{print $1}' | sort -un > ports.txt
grep 'tcp' ports.txt | cut -d '/' -f1 > ports-tcp.txt
grep 'udp' ports.txt | cut -d '/' -f1 > ports-udp.txt