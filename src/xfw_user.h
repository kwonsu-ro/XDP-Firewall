#ifndef __XFW__USER_H
#define __XFW__USER_H

#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <ctype.h>
#include "cjson/cJSON.h" // cJSON 라이브러리 필요

#include "xfw.h"

#define  JSON_PATH    "rules.json"
#define  XDP_FWD_MOD  "xfw_kern.o"
#define  XDP_FWD_SEC  "xfw"
#define  XDP_FWD_PROG "xfw_prog"

int   xfw_compare_rules( const void *a, const void *b );
int   xfw_parse_json_rules( const char *json_data, XFW_RULE *rules_out, int max_rules );
// 파일을 읽어 문자열 버퍼를 할당하고 반환하는 함수
char  *xfw_read_rule( const char *filename );

#endif
