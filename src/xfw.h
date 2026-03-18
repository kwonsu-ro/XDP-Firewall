#ifndef __XFW_H
#define __XFW_H

#include <linux/types.h>
#include <stdbool.h>

#define NIPQUAD(addr) \
    ((unsigned char *)&addr)[0], \
    ((unsigned char *)&addr)[1], \
    ((unsigned char *)&addr)[2], \
    ((unsigned char *)&addr)[3]

// CHUNK_SIZE(256) * TAILCALL_CNT(30) * MAX_PROG_SLOTS(16) = 122880
#define MAX_RULES      122880     // CHUNK_SIZE * TAILCALL_CNT * MAX_PROG_SLOTS
#define MAX_SESSIONS   122880 * 2 // 정/역방향 모두 포함
#define MAX_PROG_SLOTS 16

// Rule 정책 정의
#define XDP_ACTION_SNAT   1
#define XDP_ACTION_DNAT   2
#define XDP_ACTION_DROP   3
#define XDP_ACTION_ACCEPT 4

// XFW_RULE : Rule 데이터
typedef struct __xfw_rule 
{
    __u32 rule_id;       
    __u8  policy;        
    __u8  proto;         
    __u8  pad1;          // (명시적 패딩)
    __u8  pad2;          // (명시적 패딩)
    __be32 saddr_start;  
    __be32 saddr_end;     
    __be32 daddr_start;   
    __be32 daddr_end;     
    __be16 sport_start;   
    __be16 sport_end;     
    __be16 dport_start;   
    __be16 dport_end;     
    __be32 nat_ip;        
    __be16 nat_port;      
    __u8  padding2[2];  
} __attribute__((packed)) XFW_RULE;

// XFW_FKEY : Session 테이블의 Key로 사용
// 5-Tuple 기반 패킷 식별
typedef struct __xfw_fkey 
{
    __be32 saddr;
    __be32 daddr;
    __be16 sport;
    __be16 dport;
    __u8   proto;
} __attribute__((packed)) XFW_FKEY;

// XFW_SESS_ENTRY : Session 테이블의 Value로 사용
// 5-Tuple 기반 패킷 식별
typedef struct __xfw_sess_entry 
{
    __u32  rule_id;
    __u8   policy;      // XDP_ACTION_SNAT/DNAT 등
    __u8   is_reverse;  // 0: 정방향, 1: 역방향
    __u8   padding[2];  // 4바이트 정렬용
    __be32 nat_saddr;   // 정방향 SNAT 또는 역방향 DNAT용
    __be32 nat_daddr;   // 정방향 DNAT 또는 역방향 SNAT용
    __be16 nat_sport;
    __be16 nat_dport;
    __u64 last_seen;
} __attribute__((packed)) XFW_SESS_ENTRY;

// XFW_RULE_STATE : Slot 상태에 사용
// Rule 데이터 인덱스
typedef struct __xfw_rule_state 
{
    __u32 current_idx;     // Rule 데이터 인덱스
    __u32 tail_call_count; // Tail Call 카운트 ( ex. 0 ~ 29, 총 30 )
    __u32 prog_slot;       // 현재 실행 Slot 번호 ( 0 ~ 16 )
} XFW_RULE_STATE;

#endif
