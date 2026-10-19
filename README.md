<div align="center">

# DEADFACE CTF 2026 — Team "Double Espresso"

<img src="images/logo_deadface_ctf_2026.png" alt="DEADFACE CTF 2026 logo" width="180">

**95 / 96 challenges solved · 11,617 points · 35th place**

[📖 Read the full write-up](DEADFACE_CTF_2026_MASTER_Writeup_FINAL.md)

</div>

---

## What this is

A full technical write-up of our run at **DEADFACE CTF 2026** (Cyber Hacktics) — a three-day, story-driven CTF built around a fictional hacking crew, DEADFACE, and their campaign against a cast of fictional organizations: a hospital/medical-device vendor, a financial firm, a pharma/health network, a university, and the crew's own disposable infrastructure.

96 challenges across 18 categories. We cleared 95 of them. Every solve is documented with the actual commands, scripts, and reasoning used to get there — not just the final flag.

| | |
|---|---|
| **Team** | Double Espresso |
| **Players** | [Youssef Tarhouni](https://github.com/youssef-tarhouni) · Aymen Ladhari |
| **Event** | DEADFACE CTF 2026 (Cyber Hacktics) — 17–19 Oct 2026 |
| **Platform** | [ctf.deadface.io](https://ctf.deadface.io) |
| **Result** | 11,617 pts · 95/96 solved · 35th place |

## What's inside

The write-up walks through every category on the board, start to finish:

| Category | Highlights |
|---|---|
| **PWN** | ret2win, ROP chains, ret2libc with a double ASLR leak, an `execveat` syscall pivot |
| **Web** | SQL injection, IDOR/BOLA, SSRF via JWT mass assignment, admin privilege escalation |
| **Mobile** | APK/smali reversing, hardcoded secrets, Retrofit IDOR on a banking API |
| **Reverse Engineering** | Crackmes, XOR/AES-encrypted flags, brute-forcing an iOS PIN oracle |
| **Database Forensics** | Cross-table and cross-database SQL, statistical outlier detection (z-scores) |
| **Memory Forensics** | Volatility 3, raw memory carving, Windows scheduled-task persistence analysis |
| **Traffic Analysis** | DNS/ICMP exfiltration, SIP/SRTP/DTMF call-audio forensics, zone transfers |
| **Steganography** | Metadata forensics, printer tracking dots, progressive-JPEG payload injection |
| **Cryptography & Logic** | Vigenère variants, AES-CTR nonce reuse, Mastermind-style logic puzzles |
| **OSINT** | API-hidden data, GEOINT, whitespace steganography, social-engineering trails |

The only unsolved item is **Get That Bag** (350 pts) — a salary figure locked behind a cipher we couldn't fully break in time. The write-up documents the full investigation, including the failed attempts, because a documented dead end is still useful.

## Why this write-up

Most CTF write-ups just paste a flag with no context. This one is built the other way around: every challenge shows the *reasoning* — what we tried, what failed and why, and the exact command that finally worked — so it's as useful as a reference for the techniques as it is a record of the event.

## Tooling

`nmap` · `gobuster` / `ffuf` · `sqlmap` · `pwntools` · `gdb` · `radare2` / Ghidra · `apktool` / `jadx` · `tshark` / Wireshark · `volatility3` · `exiftool` / `binwalk` / `steghide` · `scapy` / `pylibsrtp` · `john` / `hashcat` · CyberChef · Burp Suite

## Repo structure

```
.
├── DEADFACE_CTF_2026_MASTER_Writeup_FINAL.md   ← full write-up
├── images/                                      ← screenshots referenced throughout
└── README.md
```

---

<div align="center">

*Challenge event by the DEADFACE crew, 2026.*

</div>
