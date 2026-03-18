# Firewall With XDP
본 소스코드는 XDP를 이용하여 두개의 NIC로 양방향 통신을 하는 환경에서 기본 패킷 필터링을 수행하는 프로그램이다. </br>
패킷 필터링의 대상 프로토콜은 IPv4 기반의 TCP, UDP 프로토콜이다.

# 1. 주요기능
+ Rule의 개수는 10만개 이상을 지원 <br>
+ 일치하는 Rule이 있을 경우 S/DNAT(SNAT, DNAT), DROP, Accept 기능을 수행하고 패킷을 포워딩 <br>

<br>
# 2. 네트워크 구성도
네트워크 구성도는 다음과 같다.

<img width="1626" height="244" alt="Image" src="https://github.com/user-attachments/assets/79633cd5-8c3d-4d09-8c08-50562eacabe5" />

위 그림과 같이 Client와 Server 사이에 XDP를 이용하여 enp0s3과 enp0s8 NIC 간의 양방향 통신을 하고 패킷 필터링을 수행힌다.</br>
프로그램 실행 전 사용하는 환경에 맞게 NIC와 IP설정을 한다.
> [!IMPORTANT]
> Client와 Server는 **반드시 XFW를 게이트웨어로 설정**해야 한다.

<br>
  
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
테스트 방법은 다음과 같다.

## 6.1. Server
패킷 데이터가 유입되는지 확인하기 위하여 tcpdump를 실행한다.
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

## 6.3. 패킷 데이터 확인
패킷 데이터가 유입되는지 확인한다.
```
# tcpdump -vvv -i enp0s3 -enn 'ip src 192.168.215.8 and port 22'
dropped privs to tcpdump
tcpdump: listening on enp0s3, link-type EN10MB (Ethernet), snapshot length 262144 bytes
21:59:56.560462 08:00:27:e2:b2:c8 > 08:00:27:70:91:b2, ethertype IPv4 (0x0800), length 74: (tos 0x48, ttl 64, id 8502, offset 0, flags [DF], proto TCP (6), length 60)
    192.168.215.8.49718 > 192.168.215.9.22: Flags [S], cksum 0x23de (correct), seq 3801318766, win 32120, options [mss 1460,sackOK,TS val 3258682043 ecr 0,nop,wscale 7], length 0
21:59:56.562381 08:00:27:e2:b2:c8 > 08:00:27:70:91:b2, ethertype IPv4 (0x0800), length 66: (tos 0x48, ttl 64, id 8503, offset 0, flags [DF], proto TCP (6), length 52)
    192.168.215.8.49718 > 192.168.215.9.22: Flags [.], cksum 0x6669 (correct), seq 3801318767, ack 2509406652, win 251, options [nop,nop,TS val 3258682044 ecr 2015484220], length 0
21:59:56.562381 08:00:27:e2:b2:c8 > 08:00:27:70:91:b2, ethertype IPv4 (0x0800), length 87: (tos 0x48, ttl 64, id 8504, offset 0, flags [DF], proto TCP (6), length 73)
..........
```

## 6.3. XFW 디버깅 로그 확인
XFW 디버깅 로그를 확인하여 패킷 데이터 처리를 확인한다.
```
          <idle>-0       [001] ...s2.1  1000.442529: bpf_trace_printk: Session key: saddr:[192.168.56.108] daddr:[192.168.215.9] proto:[6] sport:[45866] dport:[22]
          <idle>-0       [001] ...s2.1  1000.442531: bpf_trace_printk: Packet infor: saddr:192.168.56.108, daddr:192.168.215.9, proto:6 ifindex:[2]  current_idx:[0]
          <idle>-0       [001] ...s2.1  1000.442533: bpf_trace_printk: Match rule: rule_id:[1] policy:[1] saddr_start:[192.168.56.100] saddr_end:[192.168.56.200] daddr_start:[192.168.215.9] daddr_end:[192.168.215.9]
          <idle>-0       [001] ...s2.1  1000.442534: bpf_trace_printk: Rule Match: ID 1 -> SNAT
          <idle>-0       [001] ...s2.1  1000.442538: bpf_trace_printk: New Session Created! Policy: 1
          <idle>-0       [001] ...s2.1  1000.442538: bpf_trace_printk: NAT Policy: IP 192.168.56.108 -> 192.168.215.9
          <idle>-0       [001] ...s2.1  1000.442539: bpf_trace_printk: NAT Result: IP 192.168.215.8 -> 192.168.215.9

          <idle>-0       [000] ...s2.1  1000.442974: bpf_trace_printk: Reverse Session (Reply) hit! rule id:1, policy:1 temp_nat_addr:192.168.56.108
          <idle>-0       [000] ...s2.1  1000.442976: bpf_trace_printk: NAT Policy: IP 192.168.215.9 -> 192.168.215.8
          <idle>-0       [000] ...s2.1  1000.442976: bpf_trace_printk: NAT Result: IP 192.168.215.9 -> 192.168.56.108

          <idle>-0       [001] ...s2.1  1000.443569: bpf_trace_printk: Forward Session (New/Est) hit! rule id:1, policy:1 temp_nat_addr:192.168.215.8
          <idle>-0       [001] ...s2.1  1000.443570: bpf_trace_printk: NAT Policy: IP 192.168.56.108 -> 192.168.215.9
          <idle>-0       [001] ...s2.1  1000.443570: bpf_trace_printk: NAT Result: IP 192.168.215.8 -> 192.168.215.9
```
