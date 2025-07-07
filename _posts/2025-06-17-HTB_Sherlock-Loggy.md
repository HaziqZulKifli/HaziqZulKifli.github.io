---
layout: post
title: "HTB_Sherlock-Loggy"
date: 2025-06-17 
categories: [writeup, malware analysis]
tags: [writeup,malware analysis]
image: https://miro.medium.com/v2/resize:fit:1100/format:webp/1*DeviU290wLpHGrnrE_iWuQ.png
---

# 🐞 Malware analysis

Hack the box malware analysis challenge

## **Sherlock Scenario**

Janice from accounting is beside herself! She was contacted by the SOC to tell her that her work credentials were found on the dark web by the threat intel team. We managed to recover some files from her machine and sent them to the our REM analyst.


## **Initialazation**

Started the examination with determining the the file architecture using the file command.

<figure style="text-align:center;">
  <img src="https://miro.medium.com/v2/resize:fit:720/format:webp/1*Nbj29i8kZT-0PgwaiVVilA.png"  style="width:100%;">
  <figcaption style="text-align:center;"><em>file info</em></figcaption>
</figure>

From the command now we know that the file is :

- PE32+: This is a Windows Portable Executable (PE) file using the 64-bit format.

- x86-64 architecture: The binary is compiled for 64-bit Intel/AMD systems.

- Console application: It likely runs in a terminal window rather than a GUI.

- Windows target: We'll expect Windows API calls and likely use Ghidra with the Windows analysis options enabled.

This helps to ensure we can use the correct tools and expect the right execution as we reverse engineer the binary.

## **What is the SHA-256 hash of this malware binary?**

<figure style="text-align:center;">
  <img src="https://miro.medium.com/v2/resize:fit:720/format:webp/1*XwxhmpTqPntFkOfTsM1qaw.png"  style="width:100%;">
  <figcaption style="text-align:center;"><em>sha256sum info</em></figcaption>
</figure>

Using the sha256sum command in linux we are able to retrieve the sha-256 hash for this binary.

We compute the SHA-256 hash of the binary to uniquely identify the sample and check for known matches on malware databases.

Answer: `6acd8a362def62034cbd011e6632ba5120196e2011c83dc6045fcb28b590457c`

## **What programming language (and version) is this malware written in?**

For this task i used DIE(Detect it Easy) tool. DIE is used to analyze the executable for packing, compiler information, entropy and even the language used…

<figure style="text-align:center;">
  <img src="https://miro.medium.com/v2/resize:fit:720/format:webp/1*YmaZF4wvdqV50n5-l4Fltg.png"  style="width:100%;">
  <figcaption style="text-align:center;"><em>file language</em></figcaption>
</figure>

DIE identified the binary as a 64-bit PE file compiled in Go (Golang). This information was important for planning further analysis steps, as Go binaries have unique calling conventions and structure compared to traditional C/C++ binaries.

Answer : `Golang 1.22.3`

## **There are multiple GitHub repos referenced in the static strings. Which GitHub repo would be most likely suggest the ability of this malware to exfiltrate data?**

Since the task state that github repos referenced in static string i used the strings command to list the strings available and filter the strings to show only strings that have github in it using grep command.

<figure style="text-align:center;">
  <img src="https://miro.medium.com/v2/resize:fit:640/format:webp/1*xA_DfC3tcl26TbdwG4nn5A.png" style="width:100%;">
  <figcaption style="text-align:center;"><em>search strings for term github</em></figcaption>
</figure>

From all the github repos the one that is SUSSS is github.com/jlaffaye/ftp.
Why? This is due to the github repo may provides functionality to connect to and transfer files via FTP.

This method commonly used by attackers to exfiltrate data from a victim’s system to an external server.

<figure style="text-align:center;">
  <img src="https://miro.medium.com/v2/resize:fit:720/format:webp/1*J_FTZeZwnEBY-o27bh7Qsw.png"  style="width:100%;">
  <figcaption style="text-align:center;"><em>search strings for term github</em></figcaption>
</figure>

Answer: `github.com/jlaffaye/ftp`

## **What dependency, expressed as a GitHub repo, supports Janice’s assertion that she thought she downloaded something that can just take screenshots?**

<figure style="text-align:center;">
  <img src="https://miro.medium.com/v2/resize:fit:640/format:webp/1*r9lClFCVQb7v4KlX6GKQcw.png"  style="width:100%;">
  <figcaption style="text-align:center;"><em>github showing a screenshot functionality</em></figcaption>
</figure>


Answer: `github.com/kbinani/screenshot`

## **Which function call suggests that the malware produces a file after execution?**

During the dynamic/static analysis of the binary, we identified a call to the Windows API function `WriteFile`. This function is part of the Windows API and is typically used to write data to a file or I/O device.

<figure style="text-align:center;">
  <img src="https://miro.medium.com/v2/resize:fit:616/format:webp/1*p61SkWajX-_w8PXLlyxUxg.png"  style="width:100%;">
  <figcaption style="text-align:center;"><em>Windows API function</em></figcaption>
</figure>

Even though `CreateFile` is essential to the process, the presence of `WriteFile` in the binary strongly indicates file interaction which is often more revealing during initial triage.

<figure style="text-align:center;">
  <img src="https://miro.medium.com/v2/resize:fit:604/format:webp/1*bu4MYd0vV3hIJXFo_tf8yw.png"  style="width:100%;">
  <figcaption style="text-align:center;"><em>Windows API function</em></figcaption>
</figure>

The presence of `WriteFile` suggests that the malware creates or modifies files on the victim's system after execution.

Answer: `WriteFile`

**You observe that the malware is exfiltrating data over FTP.** 

## **What is the domain it is exfiltrating data to?**

Since the malware uses FTP for communication, I searched for the string :21 in Ghidra, which is the default FTP port.

<figure style="text-align:center;">
  <img src="https://miro.medium.com/v2/resize:fit:720/format:webp/1*1LKEL2_eaKbAujJHlQI7Fw.png"  style="width:100%;">
  <figcaption style="text-align:center;"><em>filter 21 for ftp port</em></figcaption>
</figure>

<figure style="text-align:center;">
  <img src="https://miro.medium.com/v2/resize:fit:640/format:webp/1*4erjd3LNCN53ianX0Nc4dw.png"  style="width:100%;">
  <figcaption style="text-align:center;"><em>The domain</em></figcaption>
</figure>

This led me to discover the domain the malware communicates with.

Answer: `gotthem.htb`

## **What are the threat actor’s credentials?**

Started from the main function i found main.sendFilesViaFTP() function .

<figure style="text-align:center;">
  <img src="https://miro.medium.com/v2/resize:fit:640/format:webp/1*zJnJAk36AHAbPRKsNX-bdQ.png"  style="width:100%;">
  <figcaption style="text-align:center;"><em> from main function </em></figcaption>
</figure>

This function appears to be responsible for exfiltrating data via the FTP protocol.

<figure style="text-align:center;">
  <img src="https://miro.medium.com/v2/resize:fit:640/format:webp/1*3KlHi8G1RT2b0-gXy5dcsw.png"  style="width:100%;">
  <figcaption style="text-align:center;"><em> main.sendFilesViaFTP() </em></figcaption>
</figure>

I noticed that it uses the github.com/jlaffaye/ftp Go package, which provides an FTP client implementation. This confirms that the malware leverages FTP to send files to a remote server.

Inside this function, I identified hardcoded FTP connection details. By examining the function closely in Ghidra, I found that the malware includes the server address, username, and password in plain text. These credentials are used to authenticate and upload stolen files to the attacker’s FTP server, revealing a clear intent of data exfiltration.

Answer: `NottaHacker:Cle@rtextP@ssword`

## **What file keeps getting written to disk?**

From the main function i followed a variable and found it referenced to keylog.txt. Besides, I already know it uses keylog.txt since the challenge already provided with keylog.txt.

<figure style="text-align:center;">
  <img src="https://miro.medium.com/v2/resize:fit:466/format:webp/1*gnD7IPR1sj8f-4pbdpEGVQ.png"  style="width:100%;">
  <figcaption style="text-align:center;"><em> from main function </em></figcaption>
</figure>

<figure style="text-align:center;">
  <img src="https://miro.medium.com/v2/resize:fit:640/format:webp/1*Aki1Ng4X2iGwnkK2cJVaYQ.png"  style="width:100%;">
  <figcaption style="text-align:center;"><em> found a keylog.txt text </em></figcaption>
</figure>

<figure style="text-align:center;">
  <img src="https://miro.medium.com/v2/resize:fit:640/format:webp/1*YNoxTUq7FPZWm0de2URTqw.png"  style="width:100%;">
  <figcaption style="text-align:center;"><em> located keylog.txt </em></figcaption>
</figure>

<figure style="text-align:center;">
  <img src="https://miro.medium.com/v2/resize:fit:640/format:webp/1*imXoMU1ayWd6TQ7A-9P5lw.png"  style="width:100%;">
  <figcaption style="text-align:center;"><em> the keylog.txt </em></figcaption>
</figure>

Answer: `keylog.txt`

## **When Janice changed her password, this was captured in a file. What is Janice’s username and password?**

Opened the keylog.txt file because the captured keystrokes should be recorded here. Once opened confirmed that this file record the keystrokes of the user inputted.

<figure style="text-align:center;">
  <img src="https://miro.medium.com/v2/resize:fit:640/format:webp/1*imXoMU1ayWd6TQ7A-9P5lw.png"  style="width:100%;">
  <figcaption style="text-align:center;"><em> the keylog.txt </em></figcaption>
</figure>

From this text analysed possible username and password.

<figure style="text-align:center;">
  <img src="https://miro.medium.com/v2/resize:fit:640/format:webp/1*VEAUxngLxUiTbGCGleo_OQ.png"  style="width:100%;">
  <figcaption style="text-align:center;"><em> username keystroke recorded </em></figcaption>
</figure>

<figure style="text-align:center;">
  <img src="https://miro.medium.com/v2/resize:fit:640/format:webp/1*KIHnsqS89bHEZ_XTNjT1QA.png"  style="width:100%;">
  <figcaption style="text-align:center;"><em> password keystroke recorded </em></figcaption>
</figure>

<figure style="text-align:center;">
  <img src="https://miro.medium.com/v2/resize:fit:640/format:webp/1*tSMpDa2K6LQDePLQIs0ozA.png"  style="width:100%;">
  <figcaption style="text-align:center;"><em> password keystroke recorded </em></figcaption>
</figure>

Answer: `janice:Password123`

## **What app did Janice have open the last time she ran the “screenshot app”?**

The challenge provided a screenshot, which appeared to be taken from the victim’s machine. This assumption is supported by the presence of the github.com/kbinani/screenshot package in the malware binary. This package is commonly used in Go projects to capture screen images.

<figure style="text-align:center;">
  <img src="https://miro.medium.com/v2/resize:fit:720/format:webp/1*ucqCdytF-Dx9S2Kw80SlKQ.png"  style="width:100%;">
  <figcaption style="text-align:center;"><em> The screenshot feature </em></figcaption>
</figure>

Based on the screenshot tle last opened app is solitaire.

Answer: `Solitaire`


Yeeah finally solve this challenge. Thank You for reading.

<figure style="text-align:center;">
  <img src="https://miro.medium.com/v2/resize:fit:720/format:webp/1*R-Cor8y96XoAG694JhNoQQ.png"  style="width:100%;">
  <figcaption style="text-align:center;"><em>  </em></figcaption>
</figure>