#include <linux/string.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if_vlan.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/icmp.h>
#include <arpa/inet.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include <sys/param.h>
#include <netinet/in.h>
#include <ctype.h>

#include "xfw.h"

// Tail Call이 한번 실행할 때 
// 매치 확인 할 수 있는 방화벽 Rule 갯수
#define CHUNK_SIZE   256

// Tail Call의 연속 호출 횟수
// 하나의 Slot이 연속으로 호출 할 수 있는 최대 횟수
#define TAILCALL_CNT 30

// Rule 데이터 저장
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, MAX_RULES);
    __type(key, __u32);
    __type(value, XFW_RULE);
} rule_data_map SEC(".maps");

// 실행을 이어가기 위한 프로그램 배열
// Tail Call 실형 연결
// bpf_tail_call(0)->bpf_tail_call(1) ...
struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(max_entries, MAX_PROG_SLOTS);
    __type(key, __u32);
    __type(value, __u32);
} prog_array SEC(".maps");

// 현재 검사 중인 Rule 상태 저장
// Rule 인덱스, Slot 번호
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, XFW_RULE_STATE);
} rule_state_map SEC(".maps");

// Session 정보 저장
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_SESSIONS);
    __type(key, XFW_FKEY);
    __type(value, XFW_SESS_ENTRY);
} session_map SEC(".maps");


// IP 체크섬 계산 유틸리티
static __always_inline __u16 xfw_csum_update_be32( __u16 old_csum, __be32 old_val, __be32 new_val ) 
{
    __u32 sum = 0;

    sum  = ( ~bpf_ntohs(old_csum) ) & 0xFFFF;
    sum += ( ~bpf_ntohs(old_val >> 16) ) & 0xFFFF;
    sum += ( ~bpf_ntohs(old_val & 0xFFFF) ) & 0xFFFF;
    sum += bpf_ntohs( new_val >> 16 ) & 0xFFFF;
    sum += bpf_ntohs( new_val & 0xFFFF ) & 0xFFFF;

    while ( sum >> 16 ) 
	    sum = ( sum & 0xFFFF ) + ( sum >> 16 );

    return bpf_htons( ~sum & 0xFFFF );
}

// Port 체크섬 계산 유틸리티
static __always_inline __u16 xfw_csum_update_be16( __u16 old_csum, __be16 old_val, __be16 new_val ) 
{
    __u32 sum = 0;

    sum  = ( ~bpf_ntohs(old_csum) ) & 0xFFFF;
    sum += ( ~bpf_ntohs(old_val) ) & 0xFFFF;
    sum += bpf_ntohs( new_val );

    while ( sum >> 16 ) 
	    sum = ( sum & 0xFFFF ) + ( sum >> 16 );

    return bpf_htons( ~sum & 0xFFFF );
}

// NAT 실행 및 포워딩 함수
static __always_inline int xfw_forward( struct xdp_md *ctx, struct ethhdr *eth, struct iphdr *iph, void *data_end, XFW_SESS_ENTRY *se ) 
{
	int rc = 0;

	void *l4 = (void *)iph + (iph->ihl << 2);
	
	struct tcphdr *tcp = NULL;
	struct udphdr *udp = NULL;
	struct bpf_fib_lookup fib_params = {};

	__be32 saddr = 0;
	__be32 daddr = 0;

	__be16 sport = 0;
	__be16 dport = 0;

	if ( se->policy == XDP_ACTION_DROP )
		return XDP_DROP;

	if ( se->policy == XDP_ACTION_ACCEPT )
		return XDP_PASS;

	if ( se->nat_daddr || se->nat_saddr ) 
	{
		bpf_printk("NAT Policy: IP %pI4 -> %pI4", &iph->saddr, &iph->daddr);
		// 변환 후 로그
		saddr = se->nat_saddr ? se->nat_saddr : iph->saddr;
		daddr = se->nat_daddr ? se->nat_daddr : iph->daddr;
		bpf_printk( "NAT Result: IP %pI4 -> %pI4\n", &saddr, &daddr );
	}

	if ( iph->protocol == IPPROTO_TCP ) 
	{
		tcp = l4;

		if ( (void *)(tcp + 1) > data_end ) 
			return XDP_PASS;

		if (se->nat_saddr) 
		{ 
			tcp->check = xfw_csum_update_be32(tcp->check, iph->saddr, se->nat_saddr); 
			iph->check = xfw_csum_update_be32(iph->check, iph->saddr, se->nat_saddr); 
			iph->saddr = se->nat_saddr; 
		}
		if (se->nat_daddr) 
		{ 
			tcp->check = xfw_csum_update_be32(tcp->check, iph->daddr, se->nat_daddr); 
			iph->check = xfw_csum_update_be32(iph->check, iph->daddr, se->nat_daddr); 
			iph->daddr = se->nat_daddr; 
		}
		if (se->nat_sport) 
		{ 
			tcp->check = xfw_csum_update_be16(tcp->check, tcp->source, se->nat_sport); 
			tcp->source = se->nat_sport; 
		}
		if (se->nat_dport) 
		{ 
			tcp->check = xfw_csum_update_be16(tcp->check, tcp->dest, se->nat_dport); 
			tcp->dest = se->nat_dport; 
		}

		sport = tcp->source;
		dport = tcp->dest;
	}
	else if ( iph->protocol == IPPROTO_UDP ) 
	{
		udp = l4;
		if ( (void *)(udp + 1) > data_end ) 
			return XDP_PASS;

		// UDP 체크섬은 0으로 설정하여 무력화 (IPv4 표준)
		udp->check = 0;

		if (se->nat_saddr) 
		{ 
			iph->check = xfw_csum_update_be32(iph->check, iph->saddr, se->nat_saddr); 
			iph->saddr = se->nat_saddr; 
		}
		if (se->nat_daddr) 
		{ 
			iph->check = xfw_csum_update_be32(iph->check, iph->daddr, se->nat_daddr); 
			iph->daddr = se->nat_daddr; 
		}
		if (se->nat_sport) 
			udp->source = se->nat_sport;

		if (se->nat_dport) 
			udp->dest = se->nat_dport;

		sport = udp->source;
		dport = udp->dest;
	}
	else if ( iph->protocol == IPPROTO_ICMP )
	{
		if (se->nat_saddr) 
		{ 
			iph->check = xfw_csum_update_be32(iph->check, iph->saddr, se->nat_saddr); 
			iph->saddr = se->nat_saddr; 
		}
		if (se->nat_daddr) 
		{ 
			iph->check = xfw_csum_update_be32(iph->check, iph->daddr, se->nat_daddr); 
			iph->daddr = se->nat_daddr; 
		}
		sport = 0;
		dport = 0;
	}

	fib_params.family = AF_INET;
	fib_params.l4_protocol = iph->protocol;
	fib_params.tot_len = bpf_ntohs(iph->tot_len);
	fib_params.ifindex = ctx->ingress_ifindex;
	fib_params.ipv4_src = iph->saddr; // 이미 변환된 IP
	fib_params.ipv4_dst = iph->daddr; // 이미 변환된 IP
	fib_params.sport = sport;
	fib_params.dport = dport;

	rc = bpf_fib_lookup( ctx, &fib_params, sizeof(fib_params), 0 );

	// rc 값 확인
	if ( rc == BPF_FIB_LKUP_RET_SUCCESS ) 
	{
		__builtin_memcpy( eth->h_dest, fib_params.dmac, 6 );
		__builtin_memcpy( eth->h_source, fib_params.smac, 6 );
		return bpf_redirect( fib_params.ifindex, 0 );
	}

	// rc가 0이 아니면 커널 스택에서 수행
	return XDP_PASS;

}

// Rule 매치 확인 함수
static __always_inline int xfw_match_rule( XFW_RULE *r, __u8 proto, __u32 saddr, __u32 daddr, __u16 sport, __u16 dport ) 
{

	// 프로토콜 비교
	if ( r->proto != 0 && r->proto != proto ) 
		return 0;

	// 출발지 IP 범위 비교
	if ( r->saddr_start != 0x00000000 ) 
	{
		if ( saddr < bpf_ntohl(r->saddr_start) || saddr > bpf_ntohl(r->saddr_end) ) 
			return 0;
	}

	// 목적지 IP 범위 비교
	if ( r->daddr_start != 0x00000000 ) 
	{
		if ( daddr < bpf_ntohl(r->daddr_start) || daddr > bpf_ntohl(r->daddr_end) ) 
			return 0;
	}

	// 출발지 포트 범위 비교
	if ( r->sport_start != 0 ) 
	{
		if ( sport < bpf_ntohs(r->sport_start) || sport > bpf_ntohs(r->sport_end) )
			return 0;
	}

	// 목적지 포트 범위 비교
	if ( r->dport_start != 0 ) 
	{
		if ( dport < bpf_ntohs(r->dport_start) || dport > bpf_ntohs(r->dport_end) )
			return 0;
	}

	return 1;

}


SEC("xfw")
int xfw_prog( struct xdp_md *ctx ) 
{
    int i = 0;

    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    void *l4 = NULL;

    struct ethhdr *eth = data;
    struct iphdr  *iph = NULL;
    struct tcphdr *tcp = NULL;
    struct udphdr *udp = NULL;

    __u32  key            = 0;
    __be32 temp_nat_addr  = 0;

    __be32 pkt_saddr = 0;
    __be32 pkt_daddr = 0;

    __be16 pkt_sport = 0;
    __be16 pkt_dport = 0;

    __u8  pkt_proto  = 0;

    __u32 p_saddr = 0;
    __u32 p_daddr = 0;

    __u16 p_sport = 0;
    __u16 p_dport = 0;

    XFW_FKEY fkey      = { 0 };      // Flow Key 생성
    XFW_SESS_ENTRY *se = NULL;     // 기존 Session 조회 선언

    XFW_SESS_ENTRY rev_se = { 0 }; // [역방향] Session
    XFW_FKEY rev_fkey     = { 0 };    // [역방향] 키
    XFW_SESS_ENTRY fwd_se = { 0 }; // [정방향] Session

    XFW_RULE *r           = NULL;
    XFW_RULE_STATE *state = NULL;

    // 패킷 점검 및 파싱
    if ( (void *)(eth + 1) > data_end || eth->h_proto != bpf_htons(ETH_P_IP) )
	    return XDP_PASS;

    iph = (void *)(eth + 1);
    if ( (void *)(iph + 1) > data_end )
        return XDP_PASS;

    l4 = (void *)iph + (iph->ihl << 2);

    if ( iph->protocol == IPPROTO_TCP ) 
    {
        tcp = l4;
        if ( (void *)(tcp + 1) <= data_end ) 
	{
            pkt_sport = tcp->source; // Network Byte Order 상태
            pkt_dport = tcp->dest;   // Network Byte Order 상태
        }
    } 
    else if (iph->protocol == IPPROTO_UDP ) 
    {
        udp = l4;
        if ( (void *)(udp + 1) <= data_end ) 
	{
            pkt_sport = udp->source;
            pkt_dport = udp->dest;
        }
    }

    // Session 키 생성
    fkey.saddr = iph->saddr; 
    fkey.daddr = iph->daddr; 
    fkey.proto = iph->protocol;
    fkey.sport = pkt_sport;
    fkey.dport = pkt_dport;

    // Session 조회
    se = bpf_map_lookup_elem(&session_map, &fkey);
    if ( se ) 
    {
        // Policy가 DNAT, SNAT, ACCEPT인지 체크
        if ( se->policy == XDP_ACTION_SNAT || se->policy == XDP_ACTION_DNAT || se->policy == XDP_ACTION_ACCEPT ) 
	{
		// 패킷이 들어온 경우 현재 시간 갱신
		se->last_seen = bpf_ktime_get_ns();

		// 패킷이 정방향인지 역방향 인지 확인
		// Rule의 policy를 같이 확인하여 nat ip 주소를 확인
		if ( se->is_reverse == 1 && se->policy == XDP_ACTION_DNAT )
			temp_nat_addr = se->nat_saddr;
		else if ( se->is_reverse == 0 && se->policy == XDP_ACTION_DNAT )
			temp_nat_addr = se->nat_daddr;
		else if ( se->is_reverse == 1 && se->policy == XDP_ACTION_SNAT )
			temp_nat_addr = se->nat_daddr;
		else if ( se->is_reverse == 0 && se->policy == XDP_ACTION_SNAT )
			temp_nat_addr = se->nat_saddr;

		if ( se->is_reverse ) 
		{
			bpf_printk("Reverse Session (Reply) hit! rule id:%d, policy:%u temp_nat_addr:%pI4",
					se->rule_id, se->policy, &temp_nat_addr);
		} 
		else 
		{
			bpf_printk("Forward Session (New/Est) hit! rule id:%d, policy:%u temp_nat_addr:%pI4",
					se->rule_id, se->policy, &temp_nat_addr);
		}

		// 포워딩 실행
		return xfw_forward( ctx, eth, iph, data_end, se );
        }
    }

    bpf_printk("Session key: saddr:[%pI4] daddr:[%pI4] proto:[%d] sport:[%u] dport:[%u]", 
		    &fkey.saddr, &fkey.daddr, fkey.proto, bpf_ntohs(fkey.sport), bpf_ntohs(fkey.dport) );

    key = 0;
    state = bpf_map_lookup_elem(&rule_state_map, &key);
    if (!state) 
	    return XDP_PASS;

    pkt_saddr = iph->saddr;
    pkt_daddr = iph->daddr;
    pkt_proto = iph->protocol;

    // Rule 매치를 위한 호스트 오더 변환
    p_saddr = bpf_ntohl(pkt_saddr);
    p_daddr = bpf_ntohl(pkt_daddr);
    p_sport = bpf_ntohs(pkt_sport);
    p_dport = bpf_ntohs(pkt_dport);

    // Rule 스캔 (CHUNK_SIZE만큼 순차 실행)
    #pragma unroll
    for ( i = 0; i < CHUNK_SIZE; i++ ) 
    {

	if ( state->current_idx >= MAX_RULES ) 
		break;

	// Rule 찾기
	r = bpf_map_lookup_elem( &rule_data_map, &state->current_idx );

	// Rule 매치 확인
	if ( r && xfw_match_rule( r, pkt_proto, p_saddr, p_daddr, p_sport, p_dport)  )
	{
		bpf_printk("Packet infor: saddr:%pI4, daddr:%pI4, proto:%u ifindex:[%d]  current_idx:[%d] ", 
				&pkt_saddr, &pkt_daddr, iph->protocol, ctx->ingress_ifindex, state->current_idx);

		bpf_printk("Match rule: rule_id:[%d] policy:[%d] saddr_start:[%pI4] saddr_end:[%pI4] daddr_start:[%pI4] daddr_end:[%pI4]", 
				r->rule_id, r->policy, &r->saddr_start, &r->saddr_end, &r->daddr_start, &r->daddr_end );

		state->current_idx = 0;
		state->tail_call_count = 0;
		state->prog_slot = 0;

		// Rule 매칭 성공 시
		if ( r->policy == XDP_ACTION_DROP ) 
		{
			bpf_printk("Rule Match: ID %u -> DROP\n", r->rule_id);
			return XDP_DROP; // Session 생성 없이 즉시 차단
		}

		// 모든 구조체 변수를 0으로 명시적 초기화 (쓰레기 값 방지)
		// [역방향] Session
		memset( &rev_se, 0x00, sizeof(XFW_SESS_ENTRY) );
		// [역방향] 키
		memset( &rev_fkey, 0x00, sizeof(XFW_FKEY) );
		// [정방향] Session
		memset( &fwd_se, 0x00, sizeof(XFW_SESS_ENTRY) );
		fwd_se.rule_id = r->rule_id;
		fwd_se.policy = r->policy; 
		fwd_se.is_reverse = 0; // 정방향
		fwd_se.last_seen = bpf_ktime_get_ns();
		//__u64 now = bpf_ktime_get_ns();
		//__sync_lock_test_and_set(&se->last_seen, now);

		// 역방향 Session 값 설정
		rev_se.rule_id = r->rule_id;
		rev_se.policy = r->policy;
		rev_se.is_reverse = 1; // 역방향
		rev_se.last_seen = bpf_ktime_get_ns();
		rev_fkey.proto = iph->protocol;

		switch ( r->policy )
		{
			case XDP_ACTION_DNAT:
				// [정방향] 외부 -> 내부 서버 (NAT IP)
				// 목적지 IP를 내부 서버 IP로 변경
				fwd_se.nat_daddr = r->nat_ip;
				fwd_se.nat_dport = r->nat_port;

				// [역방향 키] 내부 서버 (NAT IP) -> 외부 (키 대칭성 확보)
				fwd_se.nat_daddr = r->nat_ip;
				rev_fkey.saddr = r->nat_ip;
				rev_fkey.daddr = pkt_saddr;
				rev_fkey.sport = r->nat_port ? r->nat_port : fkey.dport;
				rev_fkey.dport = fkey.sport;

				// [역방향 액션] 출발지 IP를 'XDP IP(VIP)'로 복구
				rev_se.nat_saddr = pkt_daddr;
				rev_se.nat_sport = fkey.dport;
				bpf_printk("Rule Match: ID %u -> DNAT", r->rule_id);
				break;

			case XDP_ACTION_SNAT:
				// [정방향] 내부 서버 -> 외부 (NAT IP)
				// 출발지 IP를 XDP IP로 변경
				fwd_se.nat_saddr = r->nat_ip;
				fwd_se.nat_sport = r->nat_port;

				// [역방향 키] 외부 (NAT IP) -> 내부 서버 (키 대칭성 확보)
				rev_fkey.saddr = pkt_daddr;
				rev_fkey.daddr = r->nat_ip;
				rev_fkey.sport = fkey.dport;
				rev_fkey.dport = r->nat_port ? r->nat_port : fkey.sport;

				// [역방향 액션] 목적지 IP를 '원래 내부 사설 IP'로 복구
				rev_se.nat_daddr = pkt_saddr;
				rev_se.nat_dport = fkey.sport;
				bpf_printk("Rule Match: ID %u -> SNAT", r->rule_id);
				break;

			case XDP_ACTION_ACCEPT:
				// [역방향 키]
				rev_fkey.saddr = fkey.daddr;
				rev_fkey.daddr = fkey.saddr;
				rev_fkey.proto = fkey.proto;
				rev_fkey.sport = fkey.dport; // 포트 반전
				rev_fkey.dport = fkey.sport;  // 포트 반전

				// [역방향 액션]
				rev_se.nat_saddr = 0;
				rev_se.nat_sport = 0;
				rev_se.nat_daddr = 0;
				rev_se.nat_dport = 0;
				bpf_printk("Rule Match: ID %u -> ACCEPT", r->rule_id);
				break;

			default:
				return XDP_PASS;

		}

		// Session 테이블 업데이트 (정/역방향 한 번에)
		bpf_map_update_elem( &session_map, &fkey, &fwd_se, BPF_ANY );
		bpf_map_update_elem( &session_map, &rev_fkey, &rev_se, BPF_ANY );

		bpf_printk( "New Session Created! Policy: %u", r->policy );

		return xfw_forward( ctx, eth, iph, data_end, &fwd_se );

	}

	state->current_idx++;

    }

    //
    // Tail Call 로직
    // 
    state->tail_call_count++;

    if ( state->tail_call_count < TAILCALL_CNT ) 
    {
        // 동일한 Slot으로 Tail Call (같은 프로그램 반복)
        bpf_tail_call(ctx, &prog_array, state->prog_slot);
    } 
    else 
    {
        // Tail Call 제한(33회) 근접 시 다음 프로그램 Slot으로 릴레이
        state->tail_call_count = 0;
        state->prog_slot++;

        if (state->prog_slot < MAX_PROG_SLOTS) 
            bpf_tail_call(ctx, &prog_array, state->prog_slot);
    }

    state->current_idx = 0;
    state->tail_call_count = 0;
    state->prog_slot = 0;

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
