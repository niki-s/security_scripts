#!/bin/bash
# working with stuff from ~line 1804 in discover.sh to get fancy nmap stuff from already run scans

name=$1
echo $name

clean_and_sort(){
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

     cat $name.gnmap | grep " $i/open/tcp//https/\| $i/open/tcp//https-alt/\| $i/open/tcp//ssl|giop/\| $i/open/tcp//ssl|http/\| $i/open/tcp//ssl|unknown/" |
     sed -e 's/Host: //g' -e 's/ (.*//g' -e 's.^.https://.g' -e "s/$/:$i/g" | $sip >> tmp2
done

# sed 's/http:\/\///g' tmp > http.txt
# sed 's/https:\/\///g' tmp2 > https.txt

# Remove all empty files
find . -type f -empty -exec rm {} +
}

f_ports(){
echo "     TCP"
TCP_PORTS="13 19 21 22 23 25 37 69 70 79 80 102 110 111 119 135 139 143 389 433 443 445 465 502 512 513 514 523 524 548 554 563 587 623 631 636 771 831 873 902 993 995 998 1050 1080 1099 1158 1344 1352 1433 1521 1720 1723 1883 1911 1962 2049 2202 2375 2628 2947 3000 3031 3050 3260 3306 3310 3389 3500 3632 4369 5000 5019 5040 5060 5432 5560 5631 5632 5666 5672 5850 5900 5920 5984 5985 6000 6001 6002 6003 6004 6005 6379 6666 7210 7634 7777 8000 8009 8080 8081 8091 8140 8222 8332 8333 8400 8443 8834 9000 9084 9100 9160 9600 9999 10000 11211 12000 12345 13364 19150 27017 28784 30718 35871 37777 46824 49152 50000 50030 50060 50070 50075 50090 60010 60030"

for i in $TCP_PORTS; do
     cat $name.gnmap | grep "\<$i/open/tcp\>" | cut -d ' ' -f2 > $i.txt
done

if [[ -e 523.txt ]]; then
     mv 523.txt 523-tcp.txt
fi

if [[ -e 5060.txt ]]; then
     mv 5060.txt 5060-tcp.txt
fi

echo "     UDP"
UDP_PORTS="53 67 123 137 161 407 500 523 623 1434 1604 1900 2302 2362 3478 3671 4800 5353 5683 6481 17185 31337 44818 47808"

for i in $UDP_PORTS; do
     cat $name.gnmap | grep "\<$i/open/udp\>" | cut -d ' ' -f2 > $i.txt
done

if [[ -e 523.txt ]]; then
     mv 523.txt 523-udp.txt
fi

# Combine Apache HBase ports and sort
cat 60010.txt 60030.txt > tmp
$sip tmp > apache-hbase.txt

# Combine Bitcoin ports and sort
cat 8332.txt 8333.txt > tmp
$sip tmp > bitcoin.txt

# Combine DB2 ports and sort
cat 523-tcp.txt 523-udp.txt > tmp
$sip tmp > db2.txt

# Combine Hadoop ports and sort
cat 50030.txt 50060.txt 50070.txt 50075.txt 50090.txt > tmp
$sip tmp > hadoop.txt

# Combine NNTP ports and sort
cat 119.txt 433.txt 563.txt > tmp
$sip tmp > nntp.txt

# Combine SMTP ports and sort
cat 25.txt 465.txt 587.txt > tmp
$sip tmp > smtp.txt

# Combine X11 ports and sort
cat 6000.txt 6001.txt 6002.txt 6003.txt 6004.txt 6005.txt > tmp
$sip tmp > x11.txt

# Remove all empty files
find . -type f -empty -exec rm {} +
}

clean_and_sort
f_ports