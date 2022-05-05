# Awesome-Smart-Contract-Security ![awesome](https://awesome.re/badge.svg)
![Screenshot](img/SmartContract.png)

 


# Table of Contents
- [Blog](#blog)
- [How To's](#how-tos)
- [Paper](#paper)
- [Books](#books)
- [Course](#course)
- [Tools](#tools)
  * [Static Analysis Tools](#Static-Analysis)
  * [Dynamic Analysis Tools](#Dynamic-Analysis)
  * [Online APK Analyzers](#Online-APK-Analyzers)
  * [Online APK Decompiler](#Online-APK-Decompiler)
  * [Forensic Analysis Tools](#Forensic-Analysis)
- [Labs](#labs)
- [Talks](#talks)
- [Misc](#misc)
- [Bug Bounty & Writeups](#Bug-Bounty-&-Writeup)
- [Cheat Sheet](#Cheat-Sheet)
- [Checklist](#Checklist)
- [Bug Bounty Report](#Bug-Bounty-Report)

# Blog

* [Step-by-step guide to reverse an APK protected with DexGuard using Jadx](https://blog.lexfo.fr/dexguard.html)
* [Use cryptography in mobile apps the right way](https://blog.oversecured.com/Use-cryptography-in-mobile-apps-the-right-way/)

# How To's

* [How to analyze mobile malware: a Cabassous/FluBot Case study](https://blog.nviso.eu/2021/04/19/how-to-analyze-mobile-malware-a-cabassous-flubot-case-study/)
# Paper
* [AndrODet: An adaptive Android obfuscation detector](https://arxiv.org/pdf/1910.06192.pdf)
* [GEOST BOTNET - the discovery story of a new Android banking trojan](http://public.avast.com/research/VB2019-Garcia-etal.pdf)
* [Dual-Level Android Malware Detection](https://www.mdpi.com/2073-8994/12/7/1128)
* [An Investigation of the Android Kernel Patch Ecosystem](https://www.usenix.org/conference/usenixsecurity21/presentation/zhang)
   
# Books

 * [SEI CERT Android Secure Coding Standard](https://www.securecoding.cert.org/confluence/display/android/Android+Secure+Coding+Standard)
 * [Android Security Internals](https://www.oreilly.com/library/view/android-security-internals/9781457185496/)

# Course

* [SEC575: Mobile Device Security and Ethical Hacking](https://www.sans.org/cyber-security-courses/mobile-device-security-ethical-hacking/)

# Tools
     
#### Static Analysis

* [Deoptfuscator - Deobfuscator for Android Application](https://github.com/Gyoonus/deoptfuscator)
* [Android Reverse Engineering WorkBench for VS Code](https://github.com/Surendrajat/APKLab)
* [Apktool:A tool for reverse engineering Android apk files](https://ibotpeaches.github.io/Apktool/)
* [quark-engine - An Obfuscation-Neglect Android Malware Scoring System](https://github.com/quark-engine/quark-engine)
* [DeGuard:Statistical Deobfuscation for Android](http://apk-deguard.com/)
* [jadx - Dex to Java decompiler](https://github.com/skylot/jadx/releases)
* [Amandroid – A Static Analysis Framework](http://pag.arguslab.org/argus-saf)
* [Androwarn – Yet Another Static Code Analyzer](https://github.com/maaaaz/androwarn/)
* [Droid Hunter – Android application vulnerability analysis and Android pentest tool](https://github.com/hahwul/droid-hunter)
* [Error Prone – Static Analysis Tool](https://github.com/google/error-prone)
* [Findbugs – Find Bugs in Java Programs](http://findbugs.sourceforge.net/downloads.html)
* [Find Security Bugs – A SpotBugs plugin for security audits of Java web applications.](https://github.com/find-sec-bugs/find-sec-bugs/)
* [Flow Droid – Static Data Flow Tracker](https://github.com/secure-software-engineering/FlowDroid)
* [Smali/Baksmali – Assembler/Disassembler for the dex format](https://github.com/JesusFreke/smali)
* [Smali-CFGs – Smali Control Flow Graph’s](https://github.com/EugenioDelfa/Smali-CFGs)
* [SPARTA – Static Program Analysis for Reliable Trusted Apps](https://www.cs.washington.edu/sparta)
* [Gradle Static Analysis Plugin](https://github.com/novoda/gradle-static-analysis-plugin)
* [Checkstyle – A tool for checking Java source code](https://github.com/checkstyle/checkstyle)
* [PMD – An extensible multilanguage static code analyzer](https://github.com/pmd/pmd)
* [Soot – A Java Optimization Framework](https://github.com/Sable/soot)
* [Android Quality Starter](https://github.com/pwittchen/android-quality-starter)
* [QARK – Quick Android Review Kit](https://github.com/linkedin/qark)
* [Infer – A Static Analysis tool for Java, C, C++ and Objective-C](https://github.com/facebook/infer)
* [Android Check – Static Code analysis plugin for Android Project](https://github.com/noveogroup/android-check)
* [FindBugs-IDEA Static byte code analysis to look for bugs in Java code](https://plugins.jetbrains.com/plugin/3847-findbugs-idea)
* [APK Leaks – Scanning APK file for URIs, endpoints & secrets](https://github.com/dwisiswant0/apkleaks)
* [Trueseeing – fast, accurate and resillient vulnerabilities scanner for Android apps](https://github.com/monolithworks/trueseeing)
* [StaCoAn – crossplatform tool which aids developers, bugbounty hunters and ethical hackers](https://github.com/vincentcox/StaCoAn)
* [APKScanner](https://github.com/n3k00n3/APKScanner)
* [Mobile Audit – Web application for performing Static Analysis and detecting malware in Android APKs](https://github.com/mpast/mobileAudit)
      
#### Dynamic Analysis

* [Mobile-Security-Framework MobSF](https://github.com/MobSF/Mobile-Security-Framework-MobSF)
* [Magisk v23.0 - Root & Universal Systemless Interface](https://github.com/topjohnwu/Magisk)
* [Runtime Mobile Security (RMS) - is a powerful web interface that helps you to manipulate Android and iOS Apps at Runtime](https://github.com/m0bilesecurity/RMS-Runtime-Mobile-Security)
* [House: A runtime mobile application analysis toolkit with a Web GUI](https://github.com/nccgroup/house)
* [Objection - Runtime Mobile Exploration toolkit, powered by Frida](https://github.com/sensepost/objection)
* [Droid-FF - Android File Fuzzing Framework](https://github.com/antojoseph/droid-ff)
* [Drozer](https://github.com/FSecureLABS/drozer)
* [Inspeckage](https://github.com/ac-pm/Inspeckage)
* [PATDroid - Collection of tools and data structures for analyzing Android applications](https://github.com/mingyuan-xia/PATDroid)
* [Radare2 - Unix-like reverse engineering framework and commandline tools](https://github.com/radareorg/radare2)
* [Cutter - Free and Open Source RE Platform powered by radare2](https://cutter.re/)
* [ByteCodeViewer - Android APK Reverse Engineering Suite (Decompiler, Editor, Debugger)](https://bytecodeviewer.com/)


        
#### Online APK Analyzers

* [Guardsquare AppSweep](https://www.guardsquare.com/appsweep-mobile-application-security-testing)
* [Oversecured](https://oversecured.com/)
* [Android Observatory APK Scan](https:/androidobservatory.org/upload)
* [AndroTotal](http://andrototal.org/)
* [VirusTotal](https://www.virustotal.com/#/home/upload)
* [Scan Your APK](https://scanyourapk.com/)
* [AVC Undroid](https://undroid.av-comparatives.org/index.php)
* [OPSWAT](https://metadefender.opswat.com/#!/)
* [ImmuniWeb Mobile App Scanner](https://www.htbridge.com/mobile/)
* [Ostor Lab](https://www.ostorlab.co/scan/mobile/)
* [Quixxi](https://quixxisecurity.com/)
* [TraceDroid](http://tracedroid.few.vu.nl/submit.php)
* [Visual Threat](http://www.visualthreat.com/UIupload.action)
* [App Critique](https://appcritique.boozallen.com/)
* [Jotti's malware scan](https://virusscan.jotti.org/)
* [kaspersky scanner](https://opentip.kaspersky.com/)

#### Online APK Decompiler
* [Android APK Decompiler](http://www.decompileandroid.com/)
* [Java  Decompiler APk](http://www.javadecompilers.com/apk)
* [APK DECOMPILER APP](https://www.apkdecompilers.com/)
* [DeAPK is an open-source, online APK decompiler ](https://deapk.vaibhavpandey.com/)
* [apk and dex decompilation back to Java source code](http://www.decompiler.com/)
* [APK Decompiler Tools](https://apk.tools/tools/apk-decompiler/alternateURL/)

#### Forensic Analysis
* [Forensic Analysis for Mobile Apps (FAMA)](https://github.com/labcif/FAMA)
* [Andriller](https://github.com/den4uk/andriller)
* [Autopsy](https://www.autopsy.com/)
* [bandicoot](https://github.com/computationalprivacy/bandicoot)
* [Fridump-A universal memory dumper using Frida](https://github.com/Nightbringer21/fridump)
* [LiME - Linux Memory Extractor](https://github.com/504ensicsLabs/LiME)

# Labs

* [Damn-Vulnerable-Bank](https://github.com/rewanth1997/Damn-Vulnerable-Bank)  
* [OVAA (Oversecured Vulnerable Android App)](https://github.com/oversecured/ovaa)
* [DIVA (Damn insecure and vulnerable App)](https://github.com/payatu/diva-android)
* [OWASP Security Shepherd ](https://github.com/OWASP/SecurityShepherd)
* [Damn Vulnerable Hybrid Mobile App (DVHMA)](https://github.com/logicalhacking/DVHMA)
* [OWASP-mstg(UnCrackable Mobile Apps)](https://github.com/OWASP/owasp-mstg/tree/master/Crackmes)
* [VulnerableAndroidAppOracle](https://github.com/dan7800/VulnerableAndroidAppOracle)
* [Android InsecureBankv2](https://github.com/dineshshetty/Android-InsecureBankv2)
* [Purposefully Insecure and Vulnerable Android Application (PIIVA)](https://github.com/htbridge/pivaa)
* [Sieve app(An android application which exploits through android components)](https://github.com/mwrlabs/drozer/releases/download/2.3.4/sieve.apk)
* [DodoVulnerableBank(Insecure Vulnerable Android Application that helps to learn hacing and securing apps)](https://github.com/CSPF-Founder/DodoVulnerableBank)
* [Digitalbank(Android Digital Bank Vulnerable Mobile App)](https://github.com/CyberScions/Digitalbank)
* [AppKnox Vulnerable Application](https://github.com/appknox/vulnerable-application)
* [Vulnerable Android Application](https://github.com/Lance0312/VulnApp)
* [Android Security Labs](https://github.com/SecurityCompass/AndroidLabs)
* [Android-security Sandbox](https://github.com/rafaeltoledo/android-security)
* [VulnDroid(CTF Style Vulnerable Android App)](https://github.com/shahenshah99/VulnDroid)
* [FridaLab](https://rossmarks.uk/blog/fridalab/)
* [Santoku Linux - Mobile Security VM](https://santoku-linux.com/)
* [AndroL4b - A Virtual Machine For Assessing Android applications, Reverse Engineering and Malware Analysis](https://github.com/sh4hin/Androl4b)

  
# Talks
  
* [One Step Ahead of Cheaters -- Instrumenting Android Emulators](https://www.youtube.com/watch?v=L3AniAxp_G4)
* [Vulnerable Out of the Box: An Evaluation of Android Carrier Devices](https://www.youtube.com/watch?v=R2brQvQeTvM)
* [Rock appround the clock: Tracking malware developers by Android](https://www.youtube.com/watch?v=wd5OU9NvxjU)
* [Chaosdata - Ghost in the Droid: Possessing Android Applications with ParaSpectre](https://www.youtube.com/watch?v=ohjTWylMGEA)
* [Remotely Compromising Android and iOS via a Bug in Broadcom's Wi-Fi Chipsets](https://www.youtube.com/watch?v=TDk2RId8LFo)
* [Honey, I Shrunk the Attack Surface – Adventures in Android Security Hardening](https://www.youtube.com/watch?v=EkL1sDMXRVk)
* [Hide Android Applications in Images](https://www.youtube.com/watch?v=hajOlvLhYJY)
* [Scary Code in the Heart of Android](https://www.youtube.com/watch?v=71YP65UANP0)
* [Fuzzing Android: A Recipe For Uncovering Vulnerabilities Inside System Components In Android](https://www.youtube.com/watch?v=q_HibdrbIxo)
* [Unpacking the Packed Unpacker: Reverse Engineering an Android Anti-Analysis Native Library](https://www.youtube.com/watch?v=s0Tqi7fuOSU)
* [Android FakeID Vulnerability Walkthrough](https://www.youtube.com/watch?v=5eJYCucZ-Tc)
* [Unleashing D* on Android Kernel Drivers](https://www.youtube.com/watch?v=1XavjjmfZAY)
* [The Smarts Behind Hacking Dumb Devices](https://www.youtube.com/watch?v=yU1BrY1ZB2o)
* [Overview of common Android app vulnerabilities](https://www.bugcrowd.com/resources/webinars/overview-of-common-android-app-vulnerabilities/)
* [Advanced Android Bug Bounty skills](https://www.youtube.com/watch?v=OLgmPxTHLuY)
* [Android security architecture](https://www.youtube.com/watch?v=3asW-nBU-JU)
* [Get the Ultimate Privilege of Android Phone](https://vimeo.com/335948808)
* [Securing the System: A Deep Dive into Reversing Android Pre-Installed Apps](https://www.youtube.com/watch?v=U6qTcpCfuFc)
* [Bad Binder: Finding an Android In The Wild 0day](https://www.youtube.com/watch?v=TAwQ4ezgEIo)
* [Deep dive into ART(Android Runtime) for dynamic binary analysis](https://www.youtube.com/watch?v=mFq0vNvUgj8)
  
# Misc

* [Android Malware Adventures](https://docs.google.com/presentation/d/1pYB522E71hXrp4m3fL3E3fnAaOIboJKqpbyE5gSsOes/edit)    
* [Android-Reports-and-Resources](https://github.com/B3nac/Android-Reports-and-Resources/blob/master/README.md)
* [Hands On Mobile API Security](https://hackernoon.com/hands-on-mobile-api-security-get-rid-of-client-secrets-a79f111b6844)
* [Android Penetration Testing Courses](https://medium.com/mobile-penetration-testing/android-penetration-testing-courses-4effa36ac5ed)
* [Lesser-known Tools for Android Application PenTesting](https://captmeelo.com/pentest/2019/12/30/lesser-known-tools-for-android-pentest.html)
* [android-device-check - a set of scripts to check Android device security configuration](https://github.com/nelenkov/android-device-check)
* [apk-mitm - a CLI application that prepares Android APK files for HTTPS inspection](https://github.com/shroudedcode/apk-mitm)
* [Andriller - is software utility with a collection of forensic tools for smartphones](https://github.com/den4uk/andriller)
* [Dexofuzzy: Android malware similarity clustering method using opcode sequence-Paper](https://www.virusbulletin.com/virusbulletin/2019/11/dexofuzzy-android-malware-similarity-clustering-method-using-opcode-sequence/)
* [Chasing the Joker](https://docs.google.com/presentation/d/1sFGAERaNRuEORaH06MmZKeFRqpJo1ol1xFieUa1X_OA/edit#slide=id.p1)
* [Side Channel Attacks in 4G and 5G Cellular Networks-Slides](https://i.blackhat.com/eu-19/Thursday/eu-19-Hussain-Side-Channel-Attacks-In-4G-And-5G-Cellular-Networks.pdf)
* [Shodan.io-mobile-app for Android](https://github.com/PaulSec/Shodan.io-mobile-app)
* [Popular Android Malware 2018](https://github.com/sk3ptre/AndroidMalware_2018)
* [Popular Android Malware 2019](https://github.com/sk3ptre/AndroidMalware_2019)
* [Popular Android Malware 2020](https://github.com/sk3ptre/AndroidMalware_2020)    
    
   
# Bug Bounty & Writeup
* [Hacker101 CTF: Android Challenge Writeups](https://medium.com/bugbountywriteup/hacker101-ctf-android-challenge-writeups-f830a382c3ce)
* [Arbitrary code execution on Facebook for Android through download feature](https://medium.com/@dPhoeniixx/arbitrary-code-execution-on-facebook-for-android-through-download-feature-fb6826e33e0f)

* [RCE via Samsung Galaxy Store App](https://labs.f-secure.com/blog/samsung-s20-rce-via-samsung-galaxy-store-app/)

# Cheat Sheet 
* [Mobile Application Penetration Testing Cheat Sheet](https://github.com/sh4hin/MobileApp-Pentest-Cheatsheet)
* [ADB (Android Debug Bridge) Cheat Sheet](https://www.mobileqaengineer.com/blog/2020/2/4/adb-android-debug-bridge-cheat-sheet)
* [Frida Cheatsheet and Code Snippets for Android](https://erev0s.com/blog/frida-code-snippets-for-android/)

# Checklist
* [Android Pentesting Checklist](https://mobexler.com/checklist.htm#android)
* [OWASP Mobile Security Testing Guide (MSTG)](https://github.com/OWASP/owasp-mstg/tree/master/Checklists)
* [OWASP Mobile Application Security Verification Standard (MASVS)](https://github.com/OWASP/owasp-masvs)

# Bug Bounty Report 
* [List of Android Hackerone disclosed reports](https://github.com/B3nac/Android-Reports-and-Resources)
* [How to report security issues](https://source.android.com/security/overview/updates-resources#report-issues)
