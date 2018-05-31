 checksslv3.sh
echo | timeout 3 openssl s_client -connect $1:443 >/dev/null 2>&1; if [[ $? != 0 ]]; then echo "$1,UNKNOWN timeout or connection error"; else echo | openssl s_client -connect $1:443 -ssl3 2>&1 | grep -qo "sslv3 alert handshake failure\|SSL3_GET_RECORD:wrong version number" && echo "$1,OK Not vulnerable" || echo "$1,SSLv3 is enabled,,,SSLv3"; fi
