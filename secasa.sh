
egrep "(password|passwd) [^ ]+ encrypted" $1
egrep "^telnet [0-9]+\.[0-9]+\.[0-9]+\.[0-9]+ [0-9]+\.[0-9]+\.[0-9]+\.[0-9]+ [^ ]+" $1
egrep "ssh version 2$" $1
egrep "console timeout ([1-9]|1[0-5])$" $1
egrep "ssh timeout ([1-9]|1[0-5])$" $1
egrep "username [^ ]+ password [^ ]+ encrypted" $1
egrep "enable password [^ ]+ encrypted" $1
egrep "^snmp-server .+" $1
egrep "^snmp-server enable traps" $1
egrep "snmp-server group .+ v3" $1
egrep "Privacy Protocol: AES(256|192|128)" $1
egrep "^aaa local authentication attempts max-fail [1-3]$" $1
egrep "dhcpd enable" $1
egrep "logging console" $1
egrep "logging history (notifications|informational)" $1
egrep "logging trap (informational|debugging)" $1
egrep "logging enable" $1
egrep "logging timestamp" $1
egrep "ntp authenticate$" $1
egrep "ntp trusted-key [0-9]+" $1
egrep "ntp authentication-key [0-9]+ md5 [^ ]+" $1
egrep "timeout conn [0-9]+:[0-9]+:00" $1
egrep "timeout xlate [0-9]+:[0-9]+:00" $1
egrep "fragment chain 1 [^ ]+" $1
egrep " +inspect [ftp|http|esmtp]" $1
