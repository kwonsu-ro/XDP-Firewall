#include <errno.h>
#include <signal.h>
#include <net/if.h>
#include <sys/resource.h>
#include <time.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <xdp/libxdp.h>
#include <linux/if_link.h>

#include "xfw_user.h" // 공통 헤더

#define BUFF_NAME 64
#define SESSION_TIMEOUT_NS 60000000000ULL // 60초

static int ifindex0 = 0;
static int ifindex1 = 0;
static struct xdp_program *prog = NULL;

// 프로그램 종료 함수
static void xfw_user_close( int ret )
{
    if ( prog ) 
    {
        if ( ifindex0 != 0 ) 
	{
            printf( "\nDetaching XDP program from ifindex %d...\n", ifindex0 );
            xdp_program__detach( prog, ifindex0, XDP_MODE_SKB, 0 ); 
        }

        if ( ifindex1 != 0 ) 
	{
            printf( "Detaching XDP program from ifindex %d...\n", ifindex1 );
            xdp_program__detach(prog, ifindex1, XDP_MODE_SKB, 0); 
        }

        xdp_program__close( prog );
    }

    printf("XDP Firewall & NAT System Shutting Down.\n");

    if ( ret != 0 )
	    ret = -1;

    exit( ret );
}

// Ctrl-C 시그널 핸들러
static void xfw_int_exit( int sig ) 
{
	xfw_user_close( sig );
}

// Session 정리 스레드 함수
void xfw_session_mon( int map_fd )  
{
	__u64 now = 0;

	XFW_FKEY key      = {0};
	XFW_FKEY next_key = {0};
	XFW_SESS_ENTRY val;
	struct timespec ts;

	printf("GC Thread started.\n");
	while (1) 
	{
		clock_gettime( CLOCK_MONOTONIC, &ts );
		now = (__u64)ts.tv_sec * 1000000000ULL + ts.tv_nsec;

		memset( &key, 0, sizeof(key) );
		while ( bpf_map_get_next_key(map_fd, &key, &next_key) == 0 ) 
		{
			if ( bpf_map_lookup_elem(map_fd, &next_key, &val) == 0 ) 
			{
				if ( now - val.last_seen > SESSION_TIMEOUT_NS ) 
				{
					printf("Delete session.........\n"); 
					bpf_map_delete_elem(map_fd, &next_key);
				}
			}
			key = next_key;
		}
		sleep(5); // 5초마다 순회
	}

	return;
}

int main(int argc, char *argv[]) 
{
    
	int i        = 0;
	int ret      = 0;
	int data_fd  = 0;
	int index_fd = 0;
	int sess_fd  = 0;
	int prog_fd  = 0;

	int rule_count = 0;

	__u32 key = 0;

	char eth1_name[BUFF_NAME];
	char eth2_name[BUFF_NAME];

	char *json_content = NULL;

	struct bpf_object *obj = NULL;
	struct bpf_program *bpf_prog = NULL;

	XFW_RULE rules[MAX_RULES];

	signal(SIGINT, xfw_int_exit);
	signal(SIGTERM, xfw_int_exit);

	if (argc != 3) {
		printf("Usage: %s IFNAME_RX IFNAME_TX\n", argv[0]);
		return 1;
	}

	// 파일에서 JSON 문자열 읽기
	json_content = xfw_read_rule( JSON_PATH );
	if ( !json_content ) 
	{
		printf( "Error: Failed to read rules %s file: %s\n", JSON_PATH, strerror(errno) );
		return 1;
	}

	memset(eth1_name, 0x00, sizeof(eth1_name));
	memset(eth2_name, 0x00, sizeof(eth2_name));
	memcpy(eth1_name, argv[1], strlen(argv[1]));
	memcpy(eth2_name, argv[2], strlen(argv[2]));

	ifindex0 = if_nametoindex(eth1_name);
	ifindex1 = if_nametoindex(eth2_name);

	if (ifindex0 == 0 || ifindex1 == 0) {
		printf( "Error: Failed to get ifindex from interface names (RX: %s, TX: %s): %s\n", eth1_name, eth2_name, strerror(errno) );
		return 1;
	}

	//
	// XPD 커널 모듈 로드
	//
	prog = xdp_program__open_file( XDP_FWD_MOD, XDP_FWD_SEC, NULL );
	if ( !prog )
	{
		printf( "Error: Failed to open XDP firewall module: %s\n", strerror(errno) );
		return 1;
	}

	//
	// 인터페이스에 Attach
	//
	ret = xdp_program__attach( prog, ifindex0, XDP_MODE_SKB, 0 );
	if ( ret != 0 ) 
	{
		printf("Error: Failed to attach XDP program on RX interface %s (ifindex %d): %s\n", eth1_name, ifindex0, strerror(errno));
		xfw_user_close( 1 );
	}

	printf( "XDP program attached to RX interface %s (ifindex %d) with SKB mode.\n", eth1_name, ifindex0 );

	ret = xdp_program__attach(prog, ifindex1, XDP_MODE_SKB, 0);
	if ( ret != 0 ) 
	{
		printf("Error: Failed to attach XDP program on TX interface %s (ifindex %d): %s\n", eth2_name, ifindex1, strerror(errno));
		xfw_user_close( 1 );
	}

	printf( "XDP program attached to RX interface %s (ifindex %d) with SKB mode.\n", eth2_name, ifindex1 );

	// 맵(Map) 찾기
	obj      = xdp_program__bpf_obj(prog);
	if ( !obj )
	{
		printf("Error: Failed to attach XDP program on TX interface %s (ifindex %d): %s\n", eth2_name, ifindex1, strerror(errno));
		xfw_user_close( 1 );
	}

        index_fd = bpf_object__find_map_fd_by_name(obj, "prog_array");
	if ( index_fd == -1 )
	{
		printf( "Error: Failed to find prog_array map fd: %s\n", strerror(errno) );
		xfw_user_close( 1 );
	}

        data_fd  = bpf_object__find_map_fd_by_name(obj, "rule_data_map");
	if ( data_fd == -1 )
	{
		printf( "Error: Failed to find rule_data_map map fd: %s\n", strerror(errno) );
		xfw_user_close( 1 );
	}

        sess_fd  = bpf_object__find_map_fd_by_name(obj, "session_map");
	if ( sess_fd == -1 )
	{
		printf( "Error: Failed to find session_map map fd: %s\n", strerror(errno) );
		xfw_user_close( 1 );
	}

	// 커널 코드 함수명 확인
	bpf_prog = bpf_object__find_program_by_name(obj, XDP_FWD_PROG);
	if ( !bpf_prog )
	{
		printf( "Error: Failed to find xdp_firewall_prog program fd: %s\n", strerror(errno) );
		xfw_user_close( 1 );
	}

	// FD 추출
	prog_fd = bpf_program__fd( bpf_prog );

	// JSON Rule 파일 파싱
	rule_count = xfw_parse_json_rules( json_content, rules, MAX_RULES );
	if ( rule_count < 0 ) 
	{
		printf( "Error: Failed to JSON parsing error: %s", strerror(errno) );
		free( json_content );
		xfw_user_close( 1 );
	}

	printf( "Successfully parsed %d Rules.\n", rule_count );

	// Rule ID 기준 오름차순 정렬
	qsort( rules, rule_count, sizeof(XFW_RULE), xfw_compare_rules );

	printf( "Step 1: Updating Data Map (%d rules)...\n", rule_count );

	// Rule 맵 업데이트 (Rule 배열 순회)
	for ( i = 0; i < rule_count; i++ ) 
	{
		bpf_map_update_elem(data_fd, &i, &rules[i], BPF_ANY);
		printf("Rule ID:[%02d] Action:[%02d] proto:[%02d] "
				"saddr_start:%u.%u.%u.%u saddr_end:%u.%u.%u.%u sport_start:%5d sport_end:%5d ",
				rules[i].rule_id, rules[i].policy, rules[i].proto,
				NIPQUAD(rules[i].saddr_start), NIPQUAD(rules[i].saddr_end), ntohs(rules[i].sport_start), ntohs(rules[i].sport_end));

		printf("daddr_start:%u.%u.%u.%u daddr_end:%u.%u.%u.%u dport_start:%5d dport_end:%5d nat_ip:%u.%u.%u.%u nat_port:%5d\n", 
				NIPQUAD(rules[i].daddr_start), NIPQUAD(rules[i].daddr_end), ntohs(rules[i].dport_start), ntohs(rules[i].dport_end),
				NIPQUAD(rules[i].nat_ip), ntohs(rules[i].nat_port));
	}

	printf( "Step 2: Updating Slot Map (%d slots)...\n", MAX_PROG_SLOTS );

	// 모든 슬롯에 동일한 프로그램을 등록
	// MAX_PROG_SLOTS 갯수만큼 텔 콜을 실행하기 위한 등록
	for ( i = 0; i < MAX_PROG_SLOTS; i++ ) 
	{
		key = i;
		if ( bpf_map_update_elem(index_fd, &key, &prog_fd, BPF_ANY) != 0 ) 
		{
			fprintf(stderr, "Failed to update prog_array at slot %d\n", i);
			xfw_user_close( 1 );
		}
	}

	printf( "Successfully synchronized %d rules and their indices.\n", rule_count );

	// 메모리 해제
	free( json_content );

	while ( 1 ) 
	{
		xfw_session_mon( sess_fd ); 
		sleep(1);
	}

	xfw_user_close( 0 );
}

