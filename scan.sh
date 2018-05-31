#!/bin/bash
# use bash scan.sh 10.1.1.0/24
file1=${1?Param missing - from file. Use    scan 10.1.1.0/24    for common vulnerabilities or       scan 10.1.1.0/24 smb-vuln-ms17-010.nse }
TPATH=/tmp
DPATH=/root
FILE="$(sed s/[/]/\./g <<<$1)"


#rm $TPATH/$1
#rm $DPATH/$1.csv
#echo .
#echo ********************** START SCAN **************************
#echo .
nmap  -sC  -max-hostgroup 3 -open -script ${2:-vuln} $1 -oX $TPATH/$FILE
python nmap-parser-xml-to-csv.py $TPATH/$FILE > $DPATH/$FILE.csv
#echo ********************** END SCAN - BEGIN RESULTS ************
wc -l  $DPATH/$FILE.csv
grep VULN  $DPATH/$FILE.csv  | cut -d: -f1
