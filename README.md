# Firewall With XDP
본 소스코드는 XDP를 이용하여 두개의 NIC로 양방향 통신을 하는 환경에서 기본 패킷 필터링을 수행하는 프로그램이다. <br>
패킷 필터링의 대상 프로토콜은 IPv4 기반의 TCP, UDP 프로토콜이다.

# 1. 주요기능
+ Rule의 개수는 10만개 이상을 지원 <br>
+ 일치하는 Rule이 있을 경우 S/DNAT(SNAT, DNAT), DROP, Accept 기능을 수행하고 패킷을 포워딩 <br>
  
# 2. 네트워크 구성도
네트워크 구성도는 다음과 같다.

<img width="1626" height="244" alt="Image" src="https://github.com/user-attachments/assets/79633cd5-8c3d-4d09-8c08-50562eacabe5" />

위 그림과 같이 Client와 Server 사이에 XDP를 이용하여 enp0s3과 enp0s8 NIC 간의 양방향 통신을 하고 패킷 필터링을 수행힌다.</br>
프로그램 실행 전 사용하는 환경에 맞게 NIC와 IP설정을 한다.
> [!IMPORTANT]
> Client와 Server는 **반드시 XFW를 게이트웨어로 설정**해야 한다.

# 3. 개발환경
개발환경은 다음과 같다.
+ **VirtualBox : V 7.0**
+ **Host OS : Windows 11**
+ **Guest OS : Rocky Linux 9.4 x 3**

Guest OS는 Client, XFW, Server 모두 같은 OS를 사용한다. </br>
Client/Server와 XFW의 다른점은 XFW는 NIC가 두개이고 XDP 개발 환경을 설치해야 한다는 점이다.

## 3.1. 제약사항
+ Guest OS 네트워크의 어뎁터 종류는 **반가상 네트워크(virtio-net)** 으로 설정한다.
+ XDP는 **Generic Mode**로 사용한다. 만약 **Netive Mode**를 사용할 수 있는 환경이라면 __src/xfw_user.c__ 파일에서 **SKB Mode** 를
  **Netive Mode**로 수정하여 사용한다.

# 4. 개발환경 구축
개발환경 구축은 다음과 같다.

## 4.1. 필수 패키지 설치
필수 패키지 설치 방법은 다음과 같다.

### 4.1.1. Client/Server
```
# dnf config-manager --set-enabled crb
# dnf -y install epel-release
# dnf -y update
# dnf -y --enablerepo=devel install vim net-tools libcurl tcpdump hping3
# dnf -y install dhcp-client
# dnf -y update
# dnf -y clean all
```
### 4.1.2. XFW
```
# dnf config-manager --set-enabled crb
# dnf -y install epel-release dnf-plugins-core
# dnf -y update
# dnf -y --enablerepo=devel install dkms kernel-devel kernel-headers gcc make bzip2 elfutils-libelf-devel ntsysv vim net-tools libcurl tcpdump teamd tree initscripts systemd-devel 
# dnf -y --enablerepo=devel install clang llvm libbpf libbpf-devel libxdp libxdp-devel xdp-tools bpftool
# dnf -y install network-scripts --enablerepo=devel 
# dnf -y install glibc-devel.i686
# dnf -y install dhcp-client
# dnf -y install yara.x86_64 yara-devel.x86_64
# dnf -y install sysstat
# dnf -y update
# dnf -y clean all
```

## 4.2. XDP 개발 환경 설정

### 4.2.1. SELinux disable
SELinux는 disable하는 것을 추천한다.
```
# vim /etc/selinux/config
..........
SELINUX=disabled
..........
```

### 4.2.2. 포워딩 설정
포워딩 설정은 다음과 같다.
```
# vim /etc/sysctl.conf
..........
net.ipv4.ip_forward = 1
..........
# sysctl -p
```

# 5. 컴파일 및 실행 방법
컴파일 및 실행 방법은 다음과 같다.

## 5.1. 컴파일 방법
```
# ls
Makefile  rules.json  script  src  test
# make clean
# make
# ls
Makefile  rules.json  script  src  test  xfw_kern.o  xfw_user
#
```

## 5.2. 실행 방법
```
# ./xfw_user enp0s3 enp0s8
libbpf: elf: skipping unrecognized data section(6) xdp_metadata
libbpf: elf: skipping unrecognized data section(6) xdp_metadata
libbpf: elf: skipping unrecognized data section(6) xdp_metadata
libbpf: elf: skipping unrecognized data section(6) xdp_metadata
XDP program attached to RX interface enp0s3 (ifindex 2) with SKB mode.
libbpf: elf: skipping unrecognized data section(6) xdp_metadata
libbpf: elf: skipping unrecognized data section(6) xdp_metadata
XDP program attached to RX interface enp0s8 (ifindex 3) with SKB mode.
Successfully parsed 5 Rules.
Step 1: Updating Data Map (5 rules)...
.............
Step 2: Updating Slot Map (16 slots)...
Successfully synchronized 5 rules and their indices.
```

# 6. 테스트 방법
테스트 방법은 다음과 갇다.

## 6.1. Server
트래픽이 유입되는지 확인하기 위하여 tcpdump를 실행한다.
```
# tcpdump -vvv -i enp0s3 -enn 'ip src 192.168.215.8 and port 22'
```

## 6.2. Client
Client에서 Server로 SSH 접속을 실행한다.
```
# ssh root@192.168.215.9
root@192.168.215.9's password:
Activate the web console with: systemctl enable --now cockpit.socket

Last login: Tue Mar 17 21:26:26 2026 from 192.168.215.1
#
```

## 6.3. XFW
Client에서 보낸 패킷 데이터가 유입되는지 확인한다.
```
FORWARD Packet:PROTO:[TCP] SRC:(00:00:00:00:00:52) [10.10.56.102:1364] --> DST:(00:00:00:00:00:84) [10.10.126.4:80]
[MAC] IP:10.10.126.4 의 MAC을 갱신했습니다. MAC: 00:00:00:00:00:1c
FORWARD Packet:PROTO:[TCP] SRC:(00:00:00:00:00:1c) [10.10.126.4:80] --> DST:(00:00:00:00:00:7e) [10.10.56.102:1364]
[MAC] IP:10.10.56.102 의 MAC을 갱신했습니다. MAC: 00:00:00:00:00:52
DROP 1 Packet:PROTO:[TCP] SRC:(00:00:00:00:00:52) [10.10.56.102:1365] --> DST:(00:00:00:00:00:84) [10.10.126.4:80]
```
