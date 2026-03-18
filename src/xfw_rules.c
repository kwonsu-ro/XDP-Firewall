#include <netinet/in.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "cjson/cJSON.h" // cJSON 라이브러리 필요

#include "xfw_user.h" // 공통 헤더

#define CHECK_ITEM( ptr, name ) \
	if ( !(ptr) ) { \
		fprintf( stderr, "Error: Missing required field '%s' in rule index %d\n", (name), count ); \
		continue; \
	}

// Rule 정렬을 위한 비교 함수 (qsort용)
int xfw_compare_rules( const void *a, const void *b ) 
{
	XFW_RULE *ra = (XFW_RULE *)a;
	XFW_RULE *rb = (XFW_RULE *)b;

	if ( ra->rule_id < rb->rule_id ) return -1;
	if ( ra->rule_id > rb->rule_id ) return 1;

	return 0;
}


// 문자열 내의 공백을 제거하는 함수
void xfw_remove_spaces( char* s )
{
	char* d = s;

	do {
		while ( isspace(*s) ) s++;
	} while ( (*d++ = *s++) );
}

// IP 파싱
// CIDR 형식 : ex) 192.168.1.0/24 
// Rang 형식 : ex) 192.168.1.1~192.168.1.109
// 단일 형식 : ex) 192.168.1.1
void xfw_parse_ip_field( cJSON *item, __be32 *start, __be32 *end ) 
{
	int prefix = 0;

	char temp[128];
	char *tilde = NULL;
	char *slash = NULL;

	uint32_t addr = 0;
	uint32_t mask = 0;

	if ( !item || !item->valuestring ) 
	{
		*start = 0; 
		*end = 0; 
		return;
	}

	strncpy( temp, item->valuestring, sizeof(temp) - 1 );
	temp[sizeof(temp) - 1] = '\0';

	// 공백 제거 (ex: " 192.168.1.1 ~ 1.10 " -> "192.168.1.1~1.10")
	xfw_remove_spaces( temp );

	// 범위 형식 파싱 (ex: "192.168.1.1~192.168.1.109")
	if ( strchr(temp, '~') ) 
	{
		tilde = strchr( temp, '~' );
		*tilde = '\0';
		*start = inet_addr( temp );
		*end = inet_addr( tilde + 1 );
	}
	// CIDR 형식 파싱 (ex: "192.168.1.0/24")
	else if ( strchr(temp, '/') ) 
	{
		slash = strchr( temp, '/' );
		*slash = '\0';
		prefix = atoi( slash + 1 );

		addr = ntohl( inet_addr(temp) );
		// 0순위 방어: prefix가 0~32 범위를 벗어나지 않게 처리
		if ( prefix < 0 ) 
			prefix = 0;

		if ( prefix > 32 ) 
			prefix = 32;

		mask = ( prefix == 0 ) ? 0 : ( ~0U << (32 - prefix) );

		*start = htonl( addr & mask );       // 네트워크 시작 주소
		*end = htonl( addr | ~mask );        // 브로드캐스트 주소(범위 끝)
	}
	// 단일 IP
	else 
	{
		*start = inet_addr( temp );
		*end = *start;
	}
}

// 포트 파싱
// 범위 형식 : ex) 0~65535
// 단일 형식 : ex) 22
// 문자열("0~65535", "22")과 숫자(22) 모두 대응
void xfw_parse_port_field( cJSON *item, __be16 *start, __be16 *end ) 
{
	char temp[32];

	uint16_t p = 0;

	char *tilde = NULL;
	const char *p_str = NULL;

	if ( !item ) 
	{ 
		*start = 0; 
		*end = 0; 
		return; 
	}

	// 숫자로 들어온 경우 (ex: "dport": 22)
	if ( cJSON_IsNumber( item ) ) 
	{
		p = (uint16_t)item->valueint;
		*start = htons(p);
		*end = htons(p);
		return;
	}

	// 문자열로 들어온 경우 (ex: "sport": "0~65535")
	p_str = item->valuestring;

	// 범위 포트
	if ( strchr(p_str, '~') ) 
	{
		memcpy( temp, p_str, sizeof(temp) );
		tilde = strchr( temp, '~' );
		*tilde = '\0';
		*start = htons((uint16_t)atoi(temp));
		*end = htons((uint16_t)atoi(tilde + 1));
	} 
	// 단일 포트
	else 
	{
		p = (uint16_t)atoi(p_str);
		*start = htons(p);
		*end = htons(p);
	}
}

// Rule 파싱
int xfw_parse_json_rules( const char *json_data, XFW_RULE *rules_out, int max_rules ) 
{

    int count = 0;
    uint16_t np = 0;

    const char *act = NULL;
    const char *prt = NULL;

    cJSON *item = NULL;
    cJSON *rule_list = NULL;
    cJSON *root = cJSON_Parse( json_data );

    cJSON *id_obj = NULL;
    cJSON *policy_obj = NULL;
    cJSON *proto_obj = NULL;
    cJSON *saddr_obj = NULL;
    cJSON *daddr_obj = NULL;
    cJSON *sport_obj = NULL;
    cJSON *dport_obj = NULL;
    cJSON *nat_ip_obj = NULL;
    cJSON *nat_port_obj = NULL;

    XFW_RULE *r = NULL;

    __be32 s_start, s_end, d_start, d_end;
    __be16 sp_s, sp_e, dp_s, dp_e;

    if (!root) return -1;

    rule_list = cJSON_GetObjectItem( root, "rules" );

    cJSON_ArrayForEach( item, rule_list )
    {
	    if ( count >= max_rules ) 
		    break;

	    r = &rules_out[count];
	    memset( r, 0, sizeof(XFW_RULE) );

	    // 1. ID 처리
	    id_obj = cJSON_GetObjectItem( item, "rule_id" );
	    CHECK_ITEM(id_obj, "rule_id");
	    r->rule_id = id_obj->valueint;

	    // 2. Action 매핑 및 에러 처리
	    policy_obj = cJSON_GetObjectItem( item, "policy" );
	    CHECK_ITEM( policy_obj, "policy" );
	    act = policy_obj->valuestring;

	    if ( strcmp(act, "snat") == 0 ) r->policy = XDP_ACTION_SNAT;
	    else if ( strcmp(act, "dnat") == 0 ) r->policy = XDP_ACTION_DNAT;
	    else if ( strcmp(act, "drop") == 0 ) r->policy = XDP_ACTION_DROP;
	    else if ( strcmp(act, "accept") == 0 ) r->policy = XDP_ACTION_ACCEPT;
	    else {
		    fprintf( stderr, "Error: Unknown policy '%s' at rule %d\n", act, r->rule_id );
		    continue;
	    }

	    // 3. Proto 매핑
	    proto_obj = cJSON_GetObjectItem( item, "proto" );
	    CHECK_ITEM( proto_obj, "proto" );
	    prt = proto_obj->valuestring;

	    if ( strcmp(prt, "tcp") == 0 ) r->proto = IPPROTO_TCP;
	    else if ( strcmp(prt, "udp") == 0 ) r->proto = IPPROTO_UDP;
	    else if ( strcmp(prt, "icmp") == 0 ) r->proto = IPPROTO_ICMP;
	    else if ( strcmp(prt, "all") == 0 ) r->proto = 0;
	    else break;

	    // 4. IP 및 포트 필드 (xfw_parse 함수 내부에서 NULL 체크가 된다고 가정, 아닐 시 여기서 체크)
	    saddr_obj = cJSON_GetObjectItem( item, "saddr" );
	    daddr_obj = cJSON_GetObjectItem( item, "daddr" );
	    sport_obj = cJSON_GetObjectItem( item, "sport" );
	    dport_obj = cJSON_GetObjectItem( item, "dport" );

	    if ( !saddr_obj || !daddr_obj || !sport_obj || !dport_obj ) 
	    {
		    fprintf( stderr, "Error: Network fields (addr/port) missing in rule %d\n", r->rule_id );
		    continue;
	    }

	    xfw_parse_ip_field(saddr_obj, &s_start, &s_end);
	    xfw_parse_ip_field(daddr_obj, &d_start, &d_end);
	    r->saddr_start = s_start; r->saddr_end = s_end;
	    r->daddr_start = d_start; r->daddr_end = d_end;

	    xfw_parse_port_field(sport_obj, &sp_s, &sp_e);
	    xfw_parse_port_field(dport_obj, &dp_s, &dp_e);
	    r->sport_start = sp_s; r->sport_end = sp_e;
	    r->dport_start = dp_s; r->dport_end = dp_e;

	    // 5. NAT 필드 처리 (SNAT/DNAT일 때만 필수인 경우 대응)
	    nat_ip_obj = cJSON_GetObjectItem( item, "nat_ip" );
	    nat_port_obj = cJSON_GetObjectItem( item, "nat_port" );

	    if ( r->policy == XDP_ACTION_SNAT || r->policy == XDP_ACTION_DNAT ) 
	    {
		    if ( !nat_ip_obj || !nat_port_obj ) 
		    {
			    fprintf( stderr, "Error: NAT fields missing for NAT policy in rule %d\n", r->rule_id );
			    continue;
		    }
		    r->nat_ip = inet_addr( nat_ip_obj->valuestring );
		    np = cJSON_IsNumber( nat_port_obj ) ? (uint16_t)nat_port_obj->valueint : (uint16_t)atoi( nat_port_obj->valuestring );
		    r->nat_port = htons(np);
	    }

	    count++;
    }

    cJSON_Delete( root );

    if ( count <= 0 )
	    return -1;
    else 
	    return count;

}

// Rule 파일을 읽어 문자열 버퍼를 할당하고 반환하는 함수
char *xfw_read_rule( const char *filename ) 
{

    long size = 0;

    char *buffer = NULL;

    struct stat st;

    FILE *f = fopen( filename, "rb" );

    if ( !f ) 
    {
        perror("파일을 열 수 없습니다");
        return NULL;
    }

    // 파일 크기 계산
    fstat(fileno(f), &st);
    size = st.st_size;

    // 버퍼 할당
    buffer = (char *)malloc(size + 1);
    if ( !buffer ) 
    {
        fclose(f);
        return NULL;
    }

    // 내용 읽기
    fread( buffer, 1, size, f );
    buffer[size] = '\0';

    fclose(f);

    return buffer;
}
