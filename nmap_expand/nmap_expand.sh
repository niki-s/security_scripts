#!/bin/bash
# working with stuff from ~line 1804 in discover.sh to get fancy nmap stuff from already run scans

# defined for functions to use later
sip='sort -n -u -t . -k 1,1 -k 2,2 -k 3,3 -k 4,4'

# check for command line arguments:
#  accepts -s or --scripts to run more nmap scripts
POSITIONAL=()  # does something with positional parameters

while [[ $# -gt 0 ]] # loop through each parameter
do
key="$1"

# leaving in in case format in case I want to add more parameters later (ha! get it...in case...)
case $key in
    -s|--scripts)
    runScripts=true
    shift # past argument
    ;;
    -h|--help)
    echo "Help:"
    echo "	This script will prompt for the path to a saved nmap scan, make sure that the <name>.nmap and <name>.gnmap are in the same directory, share the same name, and that an absolute path is provided"
    echo "	-s --scripts: Run additional nmap scripts to explore the found ports and services"
    echo "	-h --help: display this help message again, if you want"
    exit 1
    shift # past argument
    ;;
esac
done

set -- "${POSITIONAL[@]}" # restore positional parameters

read -e -p  "Which nmap scan you would like to expand (/path/to/file/<name minus extension>): " name

# check if file names exist
if ! [[ -e $name.nmap ]]; then
	echo "ERROR: There is no file $name.nmap"
	echo "Please make sure you have specified the filename and/or location correctly"
	exit 2
fi
if ! [[ -e $name.gnmap ]]; then
	echo "ERROR: There is no file $name.gnmap"
	echo "Please make sure you have specified the filename and/or location correctly"
	exit 2
fi

# make a directory to store the resuls in
directory="${name}_expanded"
echo "Placing expansion results in $directory"
if ! [[ -e $directory ]]; then
	mkdir "$directory"
fi


echo "Expanding $name..."

clean_and_sort(){
# first, this only works with files named nmap.nmap in discover.sh, so there's your first problem
egrep -v '(0000:|0010:|0020:|0030:|0040:|0050:|0060:|0070:|0080:|0090:|00a0:|00b0:|00c0:|00d0:|1 hop|closed|guesses|GUESSING|filtered|fingerprint|FINGERPRINT|general purpose|initiated|latency|Network Distance|No exact OS|No OS matches|OS:|OS CPE|Please report|RTTVAR|scanned in|SF|unreachable|Warning|WARNING)' $name.nmap | sed 's/Nmap scan report for //' | sed '/^$/! b end; n; /^$/d; : end' > $directory/summary.txt

grep 'open' $directory/summary.txt | grep -v 'WARNING' | awk '{print $1}' | sort -un > $directory/ports.txt
grep 'tcp' $directory/ports.txt | cut -d '/' -f1 > $directory/ports-tcp.txt
grep 'udp' $directory/ports.txt | cut -d '/' -f1 > $directory/ports-udp.txt

grep 'open' $directory/summary.txt | grep -v 'really open' | awk '{for (i=4;i<=NF;i++) {printf "%s%s",sep, $i;sep=" "}; printf "\n"}' | sed 's/^ //' | sort -u | sed '/^$/d' > $directory/banners.txt

for i in $(cat $directory/ports-tcp.txt); do
     TCPPORT=$i
     cat $name.gnmap | grep " $i/open/tcp//http/\| $i/open/tcp//http-alt/\| $i/open/tcp//http-proxy/\| $i/open/tcp//appserv-http/" |
     sed -e 's/Host: //g' -e 's/ (.*//g' -e 's.^.http://.g' -e "s/$/:$i/g" | $sip >> tmp

     cat $name.gnmap | grep " $i/open/tcp//https/\| $i/open/tcp//https-alt/\| $i/open/tcp//ssl|giop/\| $i/open/tcp//ssl|http/\| $i/open/tcp//ssl|unknown/" |
     sed -e 's/Host: //g' -e 's/ (.*//g' -e 's.^.https://.g' -e "s/$/:$i/g" | $sip >> tmp2
done

# if the temp files get created seprate them into http and https files then delete them
if [[ -e tmp ]]; then
	#sed 's/http:\/\///g' tmp > $directory/http.txt
	mv tmp $directory/http.txt
	#rm tmp
fi
if [[ -e tmp2 ]]; then
	#sed 's/https:\/\///g' tmp2 > $directory/https.txt
	mv tmp2 $directory/https.txt
	#rm tmp2
fi

# Remove all empty files
find . -type f -empty -exec rm {} +
find $directory/ -type f -empty -exec rm {} +
}

f_ports(){
echo "     TCP"
TCP_PORTS="13 19 21 22 23 25 37 69 70 79 80 102 110 111 119 135 139 143 389 433 443 445 465 502 512 513 514 523 524 548 554 563 587 623 631 636 771 831 873 902 993 995 998 1050 1080 1099 1158 1344 1352 1433 1521 1720 1723 1883 1911 1962 2049 2202 2375 2628 2947 3000 3031 3050 3260 3306 3310 3389 3500 3632 4369 5000 5019 5040 5060 5432 5560 5631 5632 5666 5672 5850 5900 5920 5984 5985 6000 6001 6002 6003 6004 6005 6379 6666 7210 7634 7777 8000 8009 8080 8081 8091 8140 8222 8332 8333 8400 8443 8834 9000 9084 9100 9160 9600 9999 10000 11211 12000 12345 13364 19150 27017 28784 30718 35871 37777 46824 49152 50000 50030 50060 50070 50075 50090 60010 60030"

for i in $TCP_PORTS; do
     cat $name.gnmap | grep "\<$i/open/tcp\>" | cut -d ' ' -f2 > $directory/$i.txt
done

if [[ -e $directory/523.txt ]]; then
     mv $directory/523.txt $directory/523-tcp.txt
fi

if [[ -e $directory/5060.txt ]]; then
     mv $directory/5060.txt $directory/5060-tcp.txt
fi

echo "     UDP"
UDP_PORTS="53 67 123 137 161 407 500 523 623 1434 1604 1900 2302 2362 3478 3671 4800 5353 5683 6481 17185 31337 44818 47808"

for i in $UDP_PORTS; do
     cat $name.gnmap | grep "\<$i/open/udp\>" | cut -d ' ' -f2 > $directory/$i.txt
done

if [[ -e $directory/523.txt ]]; then
     mv $directory/523.txt $directory/523-udp.txt
fi

# Combine Apache HBase ports and sort
cat $directory/60010.txt $directory/60030.txt > tmp
$sip tmp > $directory/apache-hbase.txt

# Combine Bitcoin ports and sort
cat $directory/8332.txt $directory/8333.txt > tmp
$sip tmp > $directory/bitcoin.txt

# Combine DB2 ports and sort
cat $directory/523-tcp.txt $directory/523-udp.txt > tmp
$sip tmp > $directory/db2.txt

# Combine Hadoop ports and sort
cat $directory/50030.txt $directory/50060.txt $directory/50070.txt $directory/50075.txt $directory/50090.txt > tmp
$sip tmp > $directory/hadoop.txt

# Combine NNTP ports and sort
cat $directory/119.txt $directory/433.txt $directory/563.txt > tmp
$sip tmp > $directory/nntp.txt

# Combine SMTP ports and sort
cat $directory/25.txt $directory/465.txt $directory/587.txt > tmp
$sip tmp > $directory/smtp.txt

# Combine X11 ports and sort
cat $directory/6000.txt $directory/6001.txt $directory/6002.txt $directory/6003.txt $directory/6004.txt $directory/6005.txt > tmp
$sip tmp > $directory/x11.txt

# Remove all empty files
find . -type f -empty -exec rm {} +
find $directory/ -type f -empty -exec rm {} +
}



# needed for clean running of f_scripts()
f_cleanup(){
sed 's/Nmap scan report for //' tmp | sed '/^SF/d' | egrep -v '(0 of 100|afp-serverinfo:|ACCESS_DENIED|appears to be clean|cannot|closed|close|Compressors|Could not|Couldn|ctr-|Denied|denied|Did not|DISABLED|dns-nsid:|dns-service-discovery:|Document Moved|doesn|eppc-enum-processes|error|Error|ERROR|Failed to get|failed|filtered|GET|hbase-region-info:|HEAD|Host is up|Host script results|impervious|incorrect|is GREAT|latency|ldap-rootdse:|LDAP Results|Likely CLEAN|MAC Address|Mac OS X security type|nbstat:|No accounts left|No Allow|no banner|none|Nope.|not allowed|Not Found|Not Shown|not supported|NOT VULNERABLE|nrpe-enum:|ntp-info:|rdp-enum-encryption:|remaining|rpcinfo:|seconds|Security types|See http|Server not returning|Service Info|service unrecognized|Skipping|smb-check-vulns|smb-mbenum:|sorry|Starting|telnet-encryption:|Telnet server does not|TIMEOUT|Unauthorized|uncompressed|unhandled|Unknown|viewed over a secure|vnc-info:|wdb-version:)' | grep -v "Can't" | awk -v n=-2 'NR==n+1 && !NF{next} /^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/ {n=NR}1' | awk -v n=-2 'NR==n+1 && NF{print hold} /sslv2-drown:/ {n=NR;hold=$0;next}1' | awk -F '\n' 'BEGIN{RS="\n\n"}NF>3{print $0 "\n"}' > tmp4
}

f_scripts(){
# If the file for the corresponding port doesn't exist, skip
if [[ -e $directory/13.txt ]]; then
     echo "     Daytime"
     nmap -iL $directory/13.txt -Pn -n --open -p13 --script-timeout 1m --script=daytime --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $directory/script-13.txt
fi

if [[ -e $directory/21.txt ]]; then
     echo "     FTP"
     nmap -iL $directory/21.txt -Pn -n --open -p21 --script-timeout 1m --script=banner,ftp-anon,ftp-bounce,ftp-proftpd-backdoor,ftp-syst,ftp-vsftpd-backdoor,ssl*,tls-nextprotoneg -sV --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $directory/script-21.txt
fi

if [[ -e $directory/22.txt ]]; then
     echo "     SSH"
     nmap -iL $directory/22.txt -Pn -n --open -p22 --script-timeout 1m --script=sshv1,ssh2-enum-algos --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $directory/script-22.txt
fi

if [[ -e $directory/23.txt ]]; then
     echo "     Telnet"
     nmap -iL $directory/23.txt -Pn -n --open -p23 --script-timeout 1m --script=banner,cics-info,cics-enum,cics-user-enum,telnet-encryption,telnet-ntlm-info,tn3270-screen,tso-enum --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $directory/script-23.txt
fi

if [[ -e $directory/smtp.txt ]]; then
     echo "     SMTP"
     nmap -iL $directory/smtp.txt -Pn -n --open -p25,465,587 --script-timeout 1m --script=banner,smtp-commands,smtp-ntlm-info,smtp-open-relay,smtp-strangeport,smtp-enum-users,ssl*,tls-nextprotoneg -sV --script-args smtp-enum-users.methods={EXPN,RCPT,VRFY} --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $directory/script-smtp.txt
fi

if [[ -e $directory/37.txt ]]; then
     echo "     Time"
     nmap -iL $directory/37.txt -Pn -n --open -p37 --script-timeout 1m --script=rfc868-time --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $directory/script-37.txt
fi

if [[ -e $directory/53.txt ]]; then
     echo "     DNS"
     nmap -iL $directory/53.txt -Pn -n -sU --open -p53 --script-timeout 1m --script=dns-blacklist,dns-cache-snoop,dns-nsec-enum,dns-nsid,dns-random-srcport,dns-random-txid,dns-recursion,dns-service-discovery,dns-update,dns-zeustracker,dns-zone-transfer --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $directory/script-53.txt
fi

if [[ -e $directory/67.txt ]]; then
     echo "     DHCP"
     nmap -iL $directory/67.txt -Pn -n -sU --open -p67 --script-timeout 1m --script=dhcp-discover --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $directory/script-67.txt
fi

if [[ -e $directory/70.txt ]]; then
     echo "     Gopher"
     nmap -iL $directory/70.txt -Pn -n --open -p70 --script-timeout 1m --script=gopher-ls --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $directory/script-70.txt
fi

if [[ -e $directory/79.txt ]]; then
     echo "     Finger"
     nmap -iL $directory/79.txt -Pn -n --open -p79 --script-timeout 1m --script=finger --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $directory/script-79.txt
fi

if [[ -e $directory/102.txt ]]; then
     echo "     S7"
     nmap -iL $directory/102.txt -Pn -n --open -p102 --script-timeout 1m --script=s7-info --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $directory/script-102.txt
fi

if [[ -e $directory/110.txt ]]; then
     echo "     POP3"
     nmap -iL $directory/110.txt -Pn -n --open -p110 --script-timeout 1m --script=banner,pop3-capabilities,pop3-ntlm-info,ssl*,tls-nextprotoneg -sV --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $directory/script-110.txt
fi

if [[ -e $directory/111.txt ]]; then
     echo "     RPC"
     nmap -iL $directory/111.txt -Pn -n --open -p111 --script-timeout 1m --script=nfs-ls,nfs-showmount,nfs-statfs,rpcinfo --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $directory/script-111.txt
fi

if [[ -e $directory/nntp.txt ]]; then
     echo "     NNTP"
     nmap -iL $directory/nntp.txt -Pn -n --open -p119,433,563 --script-timeout 1m --script=nntp-ntlm-info --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $directory/script-nntp.txt
fi

if [[ -e $directory/123.txt ]]; then
     echo "     NTP"
     nmap -iL $directory/123.txt -Pn -n -sU --open -p123 --script-timeout 1m --script=ntp-info,ntp-monlist --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $directory/script-123.txt
fi

if [[ -e $directory/137.txt ]]; then
     echo "     NetBIOS"
     nmap -iL $directory/137.txt -Pn -n -sU --open -p137 --script-timeout 1m --script=nbstat --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     sed -i '/^MAC/{n; /.*/d}' tmp4		    # Find lines that start with MAC, and delete the following line
     sed -i '/^137\/udp/{n; /.*/d}' tmp4	# Find lines that start with 137/udp, and delete the following line
     mv tmp4 $directory/script-137.txt
fi

if [[ -e $directory/139.txt ]]; then
     echo "     SMB Vulns"
     nmap -iL $directory/139.txt -Pn -n --open -p139 --script-timeout 1m --script=smb* --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     egrep -v '(SERVICE|netbios)' tmp4 > tmp5
     sed '1N;N;/\(.*\n\)\{2\}.*VULNERABLE/P;$d;D' tmp5
     sed '/^$/d' tmp5 > tmp6
     grep -v '|' tmp6 > $directory/script-smbvulns.txt
fi

if [[ -e $directory/143.txt ]]; then
     echo "     IMAP"
     nmap -iL $directory/143.txt -Pn -n --open -p143 --script-timeout 1m --script=imap-capabilities,imap-ntlm-info,ssl*,tls-nextprotoneg -sV --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $directory/script-143.txt
fi

if [[ -e $directory/161.txt ]]; then
     echo "     SNMP"
     nmap -iL $directory/161.txt -Pn -n -sU --open -p161 --script-timeout 1m --script=snmp-hh3c-logins,snmp-info,snmp-interfaces,snmp-netstat,snmp-processes,snmp-sysdescr,snmp-win32-services,snmp-win32-shares,snmp-win32-software,snmp-win32-users -sV --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $directory/script-161.txt
fi

if [[ -e $directory/389.txt ]]; then
     echo "     LDAP"
     nmap -iL $directory/389.txt -Pn -n --open -p389 --script-timeout 1m --script=ldap-rootdse,ssl*,tls-nextprotoneg -sV --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $directory/script-389.txt
fi

if [[ -e $directory/443.txt ]]; then
     echo "     VMware"
     nmap -iL $directory/443.txt -Pn -n --open -p443 --script-timeout 1m --script=vmware-version --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $directory/script-443.txt
fi

if [[ -e $directory/445.txt ]]; then
     echo "     SMB"
     nmap -iL $directory/445.txt -Pn -n --open -p445 --script-timeout 1m --script=msrpc-enum,smb*,stuxnet-detect --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     sed -i '/^445/{n; /.*/d}' tmp4		# Find lines that start with 445, and delete the following line
     mv tmp4 $directory/script-445.txt
fi

if [[ -e $directory/500.txt ]]; then
     echo "     Ike"
     nmap -iL $directory/500.txt -Pn -n -sS -sU --open -p500 --script-timeout 1m --script=ike-version -sV --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $directory/script-500.txt
fi

if [[ -e $directory/db2.txt ]]; then
     echo "     DB2"
     nmap -iL $directory/db2.txt -Pn -n -sS -sU --open -p523 --script-timeout 1m --script=db2-das-info,db2-discover --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $directory/script-523.txt
fi

if [[ -e $directory/524.txt ]]; then
     echo "     Novell NetWare Core Protocol"
     nmap -iL $directory/524.txt -Pn -n --open -p524 --script-timeout 1m --script=ncp-enum-users,ncp-serverinfo --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $directory/script-524.txt
fi

if [[ -e $directory/548.txt ]]; then
     echo "     AFP"
     nmap -iL $directory/548.txt -Pn -n --open -p548 --script-timeout 1m --script=afp-ls,afp-path-vuln,afp-serverinfo,afp-showmount --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $directory/script-548.txt
fi

if [[ -e $directory/554.txt ]]; then
     echo "     RTSP"
     nmap -iL $directory/554.txt -Pn -n --open -p554 --script-timeout 1m --script=rtsp-methods --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $directory/script-554.txt
fi

if [[ -e $directory/623.txt ]]; then
     echo "     IPMI"
     nmap -iL $directory/623.txt -Pn -n -sU --open -p623 --script-timeout 1m --script=ipmi-version,ipmi-cipher-zero --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $directory/script-623.txt
fi

if [[ -e $directory/631.txt ]]; then
     echo "     CUPS"
     nmap -iL $directory/631.txt -Pn -n --open -p631 --script-timeout 1m --script=cups-info,cups-queue-info --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $directory/script-631.txt
fi

if [[ -e $directory/636.txt ]]; then
     echo "     LDAP/S"
     nmap -iL $directory/636.txt -Pn -n --open -p636 --script-timeout 1m --script=ldap-rootdse,ssl*,tls-nextprotoneg -sV --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $directory/script-636.txt
fi

if [[ -e $directory/873.txt ]]; then
     echo "     rsync"
     nmap -iL $directory/873.txt -Pn -n --open -p873 --script-timeout 1m --script=rsync-list-modules --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $directory/script-873.txt
fi

if [[ -e $directory/993.txt ]]; then
     echo "     IMAP/S"
     nmap -iL $directory/993.txt -Pn -n --open -p993 --script-timeout 1m --script=banner,imap-capabilities,imap-ntlm-info,ssl*,tls-nextprotoneg -sV --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $directory/script-993.txt
fi

if [[ -e $directory/995.txt ]]; then
     echo "     POP3/S"
     nmap -iL $directory/995.txt -Pn -n --open -p995 --script-timeout 1m --script=banner,pop3-capabilities,pop3-ntlm-info,ssl*,tls-nextprotoneg -sV --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $directory/script-995.txt
fi

if [[ -e $directory/1050.txt ]]; then
     echo "     COBRA"
     nmap -iL $directory/1050.txt -Pn -n --open -p1050 --script-timeout 1m --script=giop-info --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $directory/script-1050.txt
fi

if [[ -e $directory/1080.txt ]]; then
     echo "     SOCKS"
     nmap -iL $directory/1080.txt -Pn -n --open -p1080 --script-timeout 1m --script=socks-auth-info --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $directory/script-1080.txt
fi

if [[ -e $directory/1099.txt ]]; then
     echo "     RMI Registry"
     nmap -iL $directory/1099.txt -Pn -n --open -p1099 --script-timeout 1m --script=rmi-dumpregistry --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $directory/script-1099.txt
fi

if [[ -e $directory/1344.txt ]]; then
     echo "     ICAP"
     nmap -iL $directory/1344.txt -Pn -n --open -p1344 --script-timeout 1m --script=icap-info --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $directory/script-1344.txt
fi

if [[ -e $directory/1352.txt ]]; then
     echo "     Lotus Domino"
     nmap -iL $directory/1352.txt -Pn -n --open -p1352 --script-timeout 1m --script=domino-enum-users --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $directory/script-1352.txt
fi

if [[ -e $directory/1433.txt ]]; then
     echo "     MS-SQL"
     nmap -iL $directory/1433.txt -Pn -n --open -p1433 --script-timeout 1m --script=ms-sql-dump-hashes,ms-sql-empty-password,ms-sql-info,ms-sql-ntlm-info --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $directory/script-1433.txt
fi

if [[ -e $directory/1434.txt ]]; then
     echo "     MS-SQL UDP"
     nmap -iL $directory/1434.txt -Pn -n -sU --open -p1434 --script-timeout 1m --script=ms-sql-dac --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $directory/script-1434.txt
fi

if [[ -e $directory/1521.txt ]]; then
     echo "     Oracle"
     nmap -iL $directory/1521.txt -Pn -n --open -p1521 --script-timeout 1m --script=oracle-tns-version,oracle-sid-brute --script oracle-enum-users --script-args oracle-enum-users.sid=ORCL,userdb=orausers.txt --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $directory/script-1521.txt
fi

if [[ -e $directory/1604.txt ]]; then
     echo "     Citrix"
     nmap -iL $directory/1604.txt -Pn -n -sU --open -p1604 --script-timeout 1m --script=citrix-enum-apps,citrix-enum-servers --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $directory/script-1604.txt
fi

if [[ -e $directory/1723.txt ]]; then
     echo "     PPTP"
     nmap -iL $directory/1723.txt -Pn -n --open -p1723 --script-timeout 1m --script=pptp-version --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $directory/script-1723.txt
fi

if [[ -e $directory/1883.txt ]]; then
     echo "     MQTT"
     nmap -iL $directory/1883.txt -Pn -n --open -p1883 --script-timeout 1m --script=mqtt-subscribe --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $directory/script-1883.txt
fi

if [[ -e $directory/1911.txt ]]; then
     echo "     Tridium Niagara Fox"
     nmap -iL $directory/1911.txt -Pn -n --open -p1911 --script-timeout 1m --script=fox-info --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $directory/script-1911.txt
fi

if [[ -e $directory/1962.txt ]]; then
     echo "     PCWorx"
     nmap -iL $directory/1962.txt -Pn -n --open -p1962 --script-timeout 1m --script=pcworx-info --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $directory/script-1962.txt
fi

if [[ -e $directory/2049.txt ]]; then
     echo "     NFS"
     nmap -iL $directory/2049.txt -Pn -n --open -p2049 --script-timeout 1m --script=nfs-ls,nfs-showmount,nfs-statfs --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $directory/script-2049.txt
fi

if [[ -e $directory/2202.txt ]]; then
     echo "     ACARS"
     nmap -iL $directory/2202.txt -Pn -n --open -p2202 --script-timeout 1m --script=acarsd-info --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $directory/script-2202.txt
fi

if [[ -e $directory/2302.txt ]]; then
     echo "     Freelancer"
     nmap -iL $directory/2302.txt -Pn -n -sU --open -p2302 --script-timeout 1m --script=freelancer-info --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $directory/script-2302.txt
fi

if [[ -e $directory/2375.txt ]]; then
     echo "     Docker"
     nmap -iL $directory/2375.txt -Pn -n --open -p2375 --script-timeout 1m --script=docker-version --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $directory/script-2375.txt
fi

if [[ -e $directory/2628.txt ]]; then
     echo "     DICT"
     nmap -iL $directory/2628.txt -Pn -n --open -p2628 --script-timeout 1m --script=dict-info --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $directory/script-2628.txt
fi

if [[ -e $directory/2947.txt ]]; then
     echo "     GPS"
     nmap -iL $directory/2947.txt -Pn -n --open -p2947 --script-timeout 1m --script=gpsd-info --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $directory/script-2947.txt
fi

if [[ -e $directory/3031.txt ]]; then
     echo "     Apple Remote Event"
     nmap -iL $directory/3031.txt -Pn -n --open -p3031 --script-timeout 1m --script=eppc-enum-processes --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $directory/script-3031.txt
fi

if [[ -e $directory/3260.txt ]]; then
     echo "     iSCSI"
     nmap -iL $directory/3260.txt -Pn -n --open -p3260 --script-timeout 1m --script=iscsi-info --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $directory/script-3260.txt
fi

if [[ -e $directory/3306.txt ]]; then
     echo "     MySQL"
     nmap -iL $directory/3306.txt -Pn -n --open -p3306 --script-timeout 1m --script=mysql-databases,mysql-empty-password,mysql-info,mysql-users,mysql-variables --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $directory/script-3306.txt
fi

if [[ -e $directory/3310.txt ]]; then
     echo "     ClamAV"
     nmap -iL $directory/3310.txt -Pn -n --open -p3310 --script-timeout 1m --script=clamav-exec --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 > $directory/script-3310.txt
fi

if [[ -e $directory/3389.txt ]]; then
     echo "     Remote Desktop"
     nmap -iL $directory/3389.txt -Pn -n --open -p3389 --script-timeout 1m --script=rdp-vuln-ms12-020,rdp-enum-encryption --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     egrep -v '(attackers|Description|Disclosure|http|References|Risk factor)' tmp4 > $directory/script-3389.txt
fi

if [[ -e $directory/3478.txt ]]; then
     echo "     STUN"
     nmap -iL $directory/3478.txt -Pn -n -sU --open -p3478 --script-timeout 1m --script=stun-version --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $directory/script-3478.txt
fi

if [[ -e $directory/3632.txt ]]; then
     echo "     Distributed Compiler Daemon"
     nmap -iL $directory/3632.txt -Pn -n --open -p3632 --script-timeout 1m --script=distcc-cve2004-2687 --script-args="distcc-exec.cmd='id'" --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     egrep -v '(IDs|Risk factor|Description|Allows|earlier|Disclosure|Extra|References|http)' tmp4 > $directory/script-3632.txt
fi

if [[ -e $directory/3671.txt ]]; then
     echo "     KNX gateway"
     nmap -iL $directory/3671.txt -Pn -n -sU --open -p3671 --script-timeout 1m --script=knx-gateway-info --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $directory/script-3671.txt
fi

if [[ -e $directory/4369.txt ]]; then
     echo "     Erlang Port Mapper"
     nmap -iL $directory/4369.txt -Pn -n --open -p4369 --script-timeout 1m --script=epmd-info --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $directory/script-4369.txt
fi

if [[ -e $directory/5019.txt ]]; then
     echo "     Versant"
     nmap -iL $directory/5019.txt -Pn -n --open -p5019 --script-timeout 1m --script=versant-info --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $directory/script-5019.txt
fi

if [[ -e $directory/5060.txt ]]; then
     echo "     SIP"
     nmap -iL $directory/5060.txt -Pn -n --open -p5060 --script-timeout 1m --script=sip-enum-users,sip-methods --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $directory/script-5060.txt
fi

if [[ -e $directory/5353.txt ]]; then
     echo "     DNS Service Discovery"
     nmap -iL $directory/5353.txt -Pn -n -sU --open -p5353 --script-timeout 1m --script=dns-service-discovery --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $directory/script-5353.txt
fi

if [[ -e $directory/5666.txt ]]; then
     echo "     Nagios"
     nmap -iL $directory/5666.txt -Pn -n --open -p5666 --script-timeout 1m --script=nrpe-enum --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $directory/script-5666.txt
fi

if [[ -e $directory/5672.txt ]]; then
     echo "     AMQP"
     nmap -iL $directory/5672.txt -Pn -n --open -p5672 --script-timeout 1m --script=amqp-info --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $directory/script-5672.txt
fi

if [[ -e $directory/5683.txt ]]; then
     echo "     CoAP"
     nmap -iL $directory/5683.txt -Pn -n -sU --open -p5683 --script-timeout 1m --script=coap-resources --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $directory/script-5683.txt
fi

if [[ -e $directory/5850.txt ]]; then
     echo "     OpenLookup"
     nmap -iL $directory/5850.txt -Pn -n --open -p5850 --script-timeout 1m --script=openlookup-info --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $directory/script-5850.txt
fi

if [[ -e $directory/5900.txt ]]; then
     echo "     VNC"
     nmap -iL $directory/5900.txt -Pn -n --open -p5900 --script-timeout 1m --script=realvnc-auth-bypass,vnc-info,vnc-title --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $directory/script-5900.txt
fi

if [[ -e $directory/5984.txt ]]; then
     echo "     CouchDB"
     nmap -iL $directory/5984.txt -Pn -n --open -p5984 --script-timeout 1m --script=couchdb-databases,couchdb-stats --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $directory/script-5984.txt
fi

if [[ -e $directory/x11.txt ]]; then
     echo "     X11"
     nmap -iL $directory/x11.txt -Pn -n --open -p6000-6005 --script-timeout 1m --script=x11-access --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $directory/script-x11.txt
fi

if [[ -e $directory/6379.txt ]]; then
     echo "     Redis"
     nmap -iL $directory/6379.txt -Pn -n --open -p6379 --script-timeout 1m --script=redis-info --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $directory/script-6379.txt
fi

if [[ -e $directory/6481.txt ]]; then
     echo "     Sun Service Tags"
     nmap -iL $directory/6481.txt -Pn -n -sU --open -p6481 --script-timeout 1m --script=servicetags --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $directory/script-6481.txt
fi

if [[ -e $directory/6666.txt ]]; then
     echo "     Voldemort"
     nmap -iL $directory/6666.txt -Pn -n --open -p6666 --script-timeout 1m --script=voldemort-info --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $directory/script-6666.txt
fi

if [[ -e $directory/7210.txt ]]; then
     echo "     Max DB"
     nmap -iL $directory/7210.txt -Pn -n --open -p7210 --script-timeout 1m --script=maxdb-info --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $directory/script-7210.txt
fi

if [[ -e $directory/7634.txt ]]; then
     echo "     Hard Disk Info"
     nmap -iL $directory/7634.txt -Pn -n --open -p7634 --script-timeout 1m --script=hddtemp-info --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $directory/script-7634.txt
fi

if [[ -e $directory/8000.txt ]]; then
     echo "     QNX QCONN"
     nmap -iL $directory/8000.txt -Pn -n --open -p8000 --script-timeout 1m --script=qconn-exec --script-args=qconn-exec.timeout=60,qconn-exec.bytes=1024,qconn-exec.cmd="uname -a" --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $directory/script-8000.txt
fi

if [[ -e $directory/8009.txt ]]; then
     echo "     AJP"
     nmap -iL $directory/8009.txt -Pn -n --open -p8009 --script-timeout 1m --script=ajp-methods,ajp-request --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $directory/script-8009.txt
fi

if [[ -e $directory/8081.txt ]]; then
     echo "     McAfee ePO"
     nmap -iL $directory/8081.txt -Pn -n --open -p8081 --script-timeout 1m --script=mcafee-epo-agent --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $directory/script-8081.txt
fi

if [[ -e $directory/8091.txt ]]; then
     echo "     CouchBase Web Administration"
     nmap -iL $directory/8091.txt -Pn -n --open -p8091 --script-timeout 1m --script=membase-http-info --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $directory/script-8091.txt
fi

if [[ -e $directory/8140.txt ]]; then
     echo "     Puppet"
     nmap -iL $directory/8140.txt -Pn -n --open -p8140 --script-timeout 1m --script=puppet-naivesigning --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $directory/script-8140.txt
fi

if [[ -e $directory/bitcoin.txt ]]; then
     echo "     Bitcoin"
     nmap -iL $directory/bitcoin.txt -Pn -n --open -p8332,8333 --script-timeout 1m --script=bitcoin-getaddr,bitcoin-info,bitcoinrpc-info --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $directory/script-bitcoin.txt
fi

if [[ -e $directory/9100.txt ]]; then
     echo "     Lexmark"
     nmap -iL $directory/9100.txt -Pn -n --open -p9100 --script-timeout 1m --script=lexmark-config --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $directory/script-9100.txt
fi

if [[ -e $directory/9160.txt ]]; then
     echo "     Cassandra"
     nmap -iL $directory/9160.txt -Pn -n --open -p9160 --script-timeout 1m --script=cassandra-info --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $directory/script-9160.txt
fi

if [[ -e $directory/9600.txt ]]; then
     echo "     FINS"
     nmap -iL $directory/9600.txt -Pn -n --open -p9600 --script-timeout 1m --script=omron-info --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $directory/script-9600.txt
fi

if [[ -e $directory/9999.txt ]]; then
     echo "     Java Debug Wire Protocol"
     nmap -iL $directory/9999.txt -Pn -n --open -p9999 --script-timeout 1m --script=jdwp-version --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $directory/script-9999.txt
fi

if [[ -e $directory/10000.txt ]]; then
     echo "     Network Data Management"
     nmap -iL $directory/10000.txt -Pn -n --open -p10000 --script-timeout 1m --script=ndmp-fs-info,ndmp-version --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $directory/script-10000.txt
fi

if [[ -e $directory/11211.txt ]]; then
     echo "     Memory Object Caching"
     nmap -iL $directory/11211.txt -Pn -n --open -p11211 --script-timeout 1m --script=memcached-info --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $directory/script-11211.txt
fi

if [[ -e $directory/12000.txt ]]; then
     echo "     CCcam"
     nmap -iL $directory/12000.txt -Pn -n --open -p12000 --script-timeout 1m --script=cccam-version --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $directory/script-12000.txt
fi

if [[ -e $directory/12345.txt ]]; then
     echo "     NetBus"
     nmap -iL $directory/12345.txt -Pn -n --open -p12345 --script-timeout 1m --script=netbus-auth-bypass,netbus-version --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $directory/script-12345.txt
fi

if [[ -e $directory/17185.txt ]]; then
     echo "     VxWorks"
     nmap -iL $directory/17185.txt -Pn -n -sU --open -p17185 --script-timeout 1m --script=wdb-version --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $directory/script-17185.txt
fi

if [[ -e $directory/19150.txt ]]; then
     echo "     GKRellM"
     nmap -iL $directory/19150.txt -Pn -n --open -p19150 --script-timeout 1m --script=gkrellm-info --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $directory/script-19150.txt
fi

if [[ -e $directory/27017.txt ]]; then
     echo "     MongoDB"
     nmap -iL $directory/27017.txt -Pn -n --open -p27017 --script-timeout 1m --script=mongodb-databases,mongodb-info --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $directory/script-27017.txt
fi

if [[ -e $directory/31337.txt ]]; then
     echo "     BackOrifice"
     nmap -iL $directory/31337.txt -Pn -n -sU --open -p31337 --script-timeout 1m --script=backorifice-info --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $directory/script-31337.txt
fi

if [[ -e $directory/35871.txt ]]; then
     echo "     Flume"
     nmap -iL $directory/35871.txt -Pn -n --open -p35871 --script-timeout 1m --script=flume-master-info --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $directory/script-35871.txt
fi

if [[ -e $directory/44818.txt ]]; then
     echo "     EtherNet/IP"
     nmap -iL $directory/44818.txt -Pn -n -sU --open -p44818 --script-timeout 1m --script=enip-info --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $directory/script-44818.txt
fi

if [[ -e $directory/47808.txt ]]; then
     echo "     BACNet"
     nmap -iL $directory/47808.txt -Pn -n -sU --open -p47808 --script-timeout 1m --script=bacnet-info --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $directory/script-47808.txt
fi

if [[ -e $directory/49152.txt ]]; then
     echo "     Supermicro"
     nmap -iL $directory/49152.txt -Pn -n --open -p49152 --script-timeout 1m --script=supermicro-ipmi-conf --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $directory/script-49152.txt
fi

if [[ -e $directory/50000.txt ]]; then
     echo "     DRDA"
     nmap -iL $directory/50000.txt -Pn -n --open -p50000 --script-timeout 1m --script=drda-info --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $directory/script-50000.txt
fi

if [[ -e $directory/hadoop.txt ]]; then
     echo "     Hadoop"
     nmap -iL $directory/hadoop.txt -Pn -n --open -p50030,50060,50070,50075,50090 --script-timeout 1m --script=hadoop-datanode-info,hadoop-jobtracker-info,hadoop-namenode-info,hadoop-secondary-namenode-info,hadoop-tasktracker-info --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $directory/script-hadoop.txt
fi

if [[ -e $directory/apache-hbase.txt ]]; then
     echo "     Apache HBase"
     nmap -iL $directory/apache-hbase.txt -Pn -n --open -p60010,60030 --script-timeout 1m --script=hbase-master-info,hbase-region-info --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     mv tmp4 $directory/script-apache-hbase.txt
fi

rm tmp*

for x in $directory/script*; do
     if grep '|' $x > /dev/null 2>&1; then
          echo > /dev/null 2>&1
     else
          rm $x > /dev/null 2>&1
     fi
done

##############################################################################################################

# Additional tools

# if [[ -e 161.txt ]]; then
#      onesixtyone -c /usr/share/doc/onesixtyone/dict.txt -i 161.txt > onesixtyone.txt
# fi

# if [ -e 445.txt ] || [ -e 500.txt ]; then
#      echo
#      echo $medium
#      echo
#      echo -e "\x1B[1;34mRunning additional tools.\x1B[0m"
# fi

# if [[ -e 445.txt ]]; then
#      echo "     enum4linux"
#      for i in $(cat 445.txt); do
#           enum4linux -a $i | egrep -v "(Can't determine|enum4linux|Looking up status|No printers|No reply from|unknown|[E])" > tmp
#           cat -s tmp >> script-enum4linux.txt
#      done
# fi

# if [[ -e 445.txt ]]; then
#      echo "     smbclient"
#      for i in $(cat 445.txt); do
#           echo $i >> script-smbclient.txt
#           smbclient -L $i -N | grep -v 'failed' >> script-smbclient.txt 2>/dev/null
#           echo >> script-smbclient.txt
#      done
# fi

# if [[ -e 500.txt ]]; then
#      echo "     ike-scan"
#      for i in $(cat 445.txt); do
#           ike-scan -f $i >> script-ike-scan.txt
#      done
# fi

# rm tmp 2>/dev/null
}

###################
# Actually running things down here

clean_and_sort
f_ports
# dont run yet, not sure what hosts to test on
if [ "$runScripts" = true ] ; then
    echo '	Running additional nmap scripts! (but not actually)'
    #f_scripts
fi

if [[ -e tmp* ]]; then
	rm tmp*
fi
