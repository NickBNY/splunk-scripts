
#!/bin/bash 
#Script that downloads the Emerging Threats - Shadowserver C&C List, #Spamhaus 
#DROP Nets, Dshield Top Attackers, Known RBN Nets #and IPs, Compromised IP List, 
#RBN Malvertisers IP List;  AlienVault - IP Reputation Database; ZeuS Tracker - 
#IP Block List; SpyEye Tracker - IP Block List; Palevo Tracker - IP Block List; 
#SSLBL - SSL Blacklist; Malc0de Blacklist; Binary Defense Systems Artillery 
#Threat Intelligence Feed and Banlist Feedand then strips any junk/formatting 
#that can't be used and creates Splunk-ready inputs.    
#   
#Feel free to use and modify as needed   
#   
#Author: Adrian Daucourt based on work from Keith
#(http://#sysadminnygoodness.blogspot.com)   
#
# NICK
# https://reputation.alienvault.com/reputation.snort
# http://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt
# http://www.binarydefense.com/banlist.txt

#https://answers.splunk.com/answers/368085/what-are-the-open-threat-lists-optiv-threat-intel-1.html

#==============================================================================
#Fix error when calling script from Splunk
#==============================================================================
TIPATH=/tmp
unset LD_LIBRARY_PATH

cd $TIPATH
# hosts MalwareBytes

REMOTE_FILE="http://avant.it-mate.co.uk/dl/Tools/hpHosts/hosts.txt"
LOCAL_FILE="$TIPATH/malwarebytes_temp.txt"

modified=$(curl --silent --head $REMOTE_FILE | awk -F: '/^Last-Modified/ { print $2 }')
remote_ctime=$(date --date="$modified" +%s)
local_ctime=$(stat -c %z "$LOCAL_FILE")
local_ctime=$(date --date="$local_ctime" +%s)

[ $local_ctime -lt $remote_ctime ] && wget $REMOTE_FILE && cat $LOCAL_FILE | grep -v \# | cut -f2 > $TIPATH/malwarebytes.txt &&  sed -i '1iMALICIOUS_URL' $TIPATH/malwarebytes.txt &&  cp $TIPATH/malwarebytes.txt /opt/import/MALICIOUS_URL.csv

#==============================================================================
#Emerging Threats - Shadowserver C&C List, Spamhaus DROP Nets, Dshield Top
#Attackers   cat emerging-Block-IPs.txt | grep -v \# | grep -v -e '^$'  >emerging-Block-IPs_clean.txt
# sed -i 's/0\.0\/16/\*\.\*/' emerging-Block-IPs_clean.txt
# sed -i 's/0\/2[0-9]/\*/' emerging-Block-IPs_clean.txt
sed -i -E 's/([0-9]+)\.0\/1[0-9]/\*\.\*/' emerging-Block-IPs_clean.txt
# sed -i '1iMALICIOUS_IP' emerging-Block-IPs_clean.txt
cp emerging-Block-IPs_clean.txt /opt/import/MALICIOUS_IP.csv
#==============================================================================
curl -sI http://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt | awk -F': ' '/Modified: /{print $2}' > $TIPATH/emerging-Block-IPs.new


wget http://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt
echo "# Generated: `date`" > /home/ubuntu/downloads/emerging_threats_shadowserver_ips.txt
cat $TIPATH/emerging-Block-IPs.txt | sed -e '1,/# \Feodo/d' -e '/#/,$d' | sed -n '/^[0-9]/p' | sed 's/$/,Spamhous/' >> $TIPATH/emerging_threats_shadowserver_ips.txt

echo "# Generated: `date`" > $TIPATH/emerging_threats_spamhaus_drop_ips.txt
cat $TIPATH/emerging-Block-IPs.txt | sed -e '1,/#Spamhaus DROP Nets/d' -e '/#/,$d'  | sed -n '/^[0-9]/p' | sed 's/$/,Spamhaus-Net/' >> $TIPATH/emerging_threats_spamhaus_drop_ips.txt

echo "# Generated: `date`" > $TIPATH/emerging_threats_dshield_ips.txt

cat $TIPATH/emerging-Block-IPs.txt | sed -e '1,/#Dshield Top Attackers/d' -e '/#/,$d' | xargs -n 1 prips | sed -n '/^[0-9]/p' | sed 's/$/ Dshield IP/' >> $TIPATH/emerging_threats_dshield_ips.txt

#rm $TIPATH/emerging-Block-IPs.txt

#==============================================================================
#Emerging Threats - Compromised IP List
#==============================================================================

wget http://rules.emergingthreats.net/blockrules/compromised-ips.txt  --no-check-certificate -N

echo "# Generated: `date`" > $TIPATH/emerging_threats_compromised_ips.txt

cat $TIPATH/compromised-ips.txt | sed -n '/^[0-9]/p' | sed 's/$/ Compromised IP/' >> $TIPATH/emerging_threats_compromised_ips.txt

rm $TIPATH/compromised-ips.txt

#==============================================================================
#Binary Defense Systems Artillery Threat Intelligence Feed and Banlist Feed
#==============================================================================

wget http://www.binarydefense.com/banlist.txt -O $TIPATH/binary_defense_ips.txt --no-check-certificate -N

echo "# Generated: `date`" > $TIPATH/binary_defense_ban_list.txt

cat $TIPATH/binary_defense_ips.txt | sed -n '/^[0-9]/p' | sed 's/$/ Binary Defense IP/' >> $TIPATH/binary_defense_ban_list.txt

rm $TIPATH/binary_defense_ips.txt

#==============================================================================
#AlienVault - IP Reputation Database
#==============================================================================

wget https://reputation.alienvault.com/reputation.snort.gz -P $TIPATH --no-check-certificate -N

gzip -d $TIPATH/reputation.snort.gz

echo "# Generated: `date`" > $TIPATH/av_ip_rep_list.txt

cat $TIPATH/reputation.snort | sed -n '/^[0-9]/p' | sed "s/# //">> 
$TIPATH/av_ip_rep_list.txt

rm $TIPATH/reputation.snort

#==============================================================================
#SSLBL - SSL Blacklist
#==============================================================================

wget https://sslbl.abuse.ch/blacklist/sslipblacklist.csv -O $TIPATH/sslipblacklist.csv --no-check-certificate -N

echo "# Generated: `date`" > $TIPATH/sslipblacklist.txt

cat $TIPATH/sslipblacklist.csv | sed -n '/^[0-9]/p' | cut -d',' -f1,3 | sed "s/,/ /" | sed 's/$/ SSLBL IP/' >> $TIPATH/sslipblacklist.txt

rm $TIPATH/sslipblacklist.csv

#==============================================================================
#ZeuS Tracker - IP Block List
#==============================================================================

wget https://zeustracker.abuse.ch/blocklist.php?download=ipblocklist -O 
$TIPATH/zeustracker.txt --no-check-certificate -N

echo "# Generated: `date`" > $TIPATH/zeus_ip_block_list.txt

cat $TIPATH/zeustracker.txt | sed -n '/^[0-9]/p' | sed 's/$/ Zeus IP/' >> 
$TIPATH/zeus_ip_block_list.txt

rm $TIPATH/zeustracker.txt

#==============================================================================
#SpyEye Tracker - IP Block List
#==============================================================================

wget https://spyeyetracker.abuse.ch/blocklist.php?download=ipblocklist -O 
$TIPATH/spyeyetracker.txt --no-check-certificate -N

echo "# Generated: `date`" > $TIPATH/spyeye_ip_block_list.txt

cat $TIPATH/spyeyetracker.txt | sed -n '/^[0-9]/p' | sed 's/$/ Spyeye IP/' >> $TIPATH/spyeye_ip_block_list.txt

rm $TIPATH/spyeyetracker.txt

#==============================================================================
#Palevo Tracker - IP Block List
#==============================================================================

wget https://palevotracker.abuse.ch/blocklists.php?download=ipblocklist -O 
$TIPATH/palevotracker.txt --no-check-certificate -N

echo "# Generated: `date`" > $TIPATH/palevo_ip_block_list.txt

cat $TIPATH/palevotracker.txt | sed -n '/^[0-9]/p' | sed 's/$/ Palevo IP/' >> 
$TIPATH/palevo_ip_block_list.txt

rm $TIPATH/palevotracker.txt

#==============================================================================
#Malc0de - Malc0de Blacklist
#==============================================================================

wget http://malc0de.com/bl/IP_Blacklist.txt -O $TIPATH/IP_Blacklist.txt 
--no-check-certificate -N

echo "# Generated: `date`" > $TIPATH/malc0de_black_list.txt

cat $TIPATH/IP_Blacklist.txt | sed -n '/^[0-9]/p' | sed 's/$/ Malc0de IP/' >> 
$TIPATH/malc0de_black_list.txt

rm $TIPATH/IP_Blacklist.txt
