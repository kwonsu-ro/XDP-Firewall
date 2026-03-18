#!/bin/sh

. /etc/init.d/functions

FLAG=$1
BASENAME=`basename $0`
NIC=virtio
LIST_NIC="enp0s3 enp0s8"
SRC=./src

function xfw_CPUs( )
{

	LIST=`cat /proc/interrupts | grep $NIC | awk '{print $1}' | awk -F : '{print $1}'`

        # 하드웨어 레벨 분산 (RSS: Receive Side Scaling)
	# smp_affinity	
	#    하드웨어 인터럽트(IRQ)를 특정 CPU 코어에 할당. 
	#    NIC가 패킷을 받고 데이터 왔다라고 알릴 CPU를 지정 (IRQ 번호별)
	#
        # 소프트웨어 레벨 분산 (RPS: Receive Packet Steering)
        # rps_cpus	
	#    소프트웨어(커널) 레벨에서 패킷 처리를 다른 CPU로 분산시키는 비트마스크 (RX 큐별)
        # rps_flow_cnt	
	#    특정 네트워크 큐(RX Queue)가 처리할 수 있는 최대 동시 흐름(Flow) 수를 설정 (RX 큐별)
        # rps_sock_flow_entries	
	#    전체 시스템에서 관리할 총 소켓 흐름의 개수. 위 rps_flow_cnt들의 합보다 크거나 같아야 함

	# 1. 인터럽트 바인딩 (두 CPU 모두 활용: 3 -> 2^0 + 2^1)
	# 19번, 16번 IRQ를 CPU 0과 1 양쪽에서 받도록 설정
	for sub in $LIST;do
		echo 3 > /proc/irq/$sub/smp_affinity
	done

	# 2. RPS 설정 (두 CPU 모두 활용: 3 -> 2^0 + 2^1)
	# 패킷 처리를 CPU 0과 1 양쪽이 골고루 나눠 가짐
	for sub in $LIST_NIC;do
		echo 3 > /sys/class/net/$sub/queues/rx-0/rps_cpus
	done

	# 3. 해시 테이블 크기 최적화 (큐당 32768)
	echo 65536 > /proc/sys/net/core/rps_sock_flow_entries
	for sub in $LIST_NIC;do
		echo 32768 > /sys/class/net/$sub/queues/rx-0/rps_flow_cnt
	done

}

function xfw_CPUs_state( )
{
	mpstat -P ALL 1
}

function xfw_ret( )
{
	if [ $1 -eq 0 ];then
		echo_success
	else
		echo_failure
	fi
}

function xfw_unload( )
{
	for sub in $LIST_NIC;do
		xdp-loader unload -a $sub 1> /dev/null 2> /dev/null
	done

	kill -9 `pidof xfw_user` 1> /dev/null 2> /dev/null
}

function xfw_load( )
{
	xfw_unload
	rm -rf /sys/fs/bpf/xdp/*
#sleep 3
#xdp-loader load -vv -m skb -s xfw enp0s3 xfw_kern.o 
#sleep 3
#xdp-loader load -vv -m skb -s xfw enp0s8 xfw_kern.o
#sleep 3

	if [ ! -e "../xfw_user" ];then
		return 1;
	fi

	#CPU

	for sub in $LIST_NIC;do
		NICS_STR+="${sub} "
	done

	# Distributed Processing
	xfw_CPUs

	# Execute
	cd ..
	./xfw_user $NICS_STR 1> /dev/null 2> /dev/null &
	cd - 1> /dev/null

	sleep 1

	# Execute check
	RET=`ps -ef | grep xfw_user | grep -v grep`
	if [ "$RET" == "" ];then
		return 1;
	fi

	return 0

}

function xfw_compile( )
{
	xfw_unload

	cd ../
	if [ ! -e "Makefile" ];then
		rm -rf ./xfw_user.o ./xfw_rules.o ./xfw_kern.o ./xfw_user ../xfw_user ../xfw_kern.o 1> /dev/null 2> /dev/null
		gcc -g -Wall -O2   -c -o ./xfw_user.o ./xfw_user.c 1> /dev/null 2> /dev/null
		[ $? -ne 0 ] && return 1

		gcc -g -Wall -O2   -c -o ./xfw_rules.o ./xfw_rules.c 1> /dev/null 2> /dev/null
		[ $? -ne 0 ] && return 1

		gcc -o ./xfw_user ./xfw_user.o ./xfw_rules.o -lcjson -lxdp -lbpf -lpthread -lz 1> /dev/null 2> /dev/null
		[ $? -ne 0 ] && return 1

		clang -O2 -g -Wall -target bpf -c ./xfw_kern.c -o ./xfw_kern.o 1> /dev/null 2> /dev/null
		[ $? -ne 0 ] && return 1

		cp -dpr ./xfw_kern.o ../xfw_kern.o 1> /dev/null 2> /dev/null
		cp -dpr ./xfw_user ../xfw_user 1> /dev/null 2> /dev/null
	else
		make 1> /dev/null 2> /dev/null
		[ $? -ne 0 ] && return 1
	fi
	cd - 1> /dev/null

	return 0;
}

function xfw_dlog( )
{
	# Setup debug
	echo 1 > /sys/kernel/debug/tracing/tracing_on
	echo 8192 > /sys/kernel/debug/tracing/buffer_size_kb

	# Print debug log
	cat /sys/kernel/debug/tracing/trace_pipe
}

function xfw_ctrl( )
{
	case $FLAG in
		
		"load")
			echo -n "Start XDP Firewall Load"
			xfw_load; xfw_ret $?;echo
			;;
		"unload")
			echo -n "Start XDP Firewall Unload"
			xfw_unload; echo_success;echo
			;;
		"reload")
			echo -n "Start XDP Firewall Reload"
			xfw_unload
			xfw_load; xfw_ret $?;echo
			;;
		"compile")
			echo -n "Start XDP Firewall Compile"
			xfw_compile; xfw_ret $?;echo 
			;;
		"debug")
			echo "Start XDP Firewall Debugging"
			xfw_dlog; 
			;;
		"mcpus")
			echo "Start XDP Firewall CPUs state"
			xfw_CPUs_state
			;;
		*)
			echo "Usage: $BASENAME <load|unload|reload|compile|debug|mcpus>"
			exit 1;

	esac
}

xfw_ctrl
