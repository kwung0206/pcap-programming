#include <arpa/inet.h>
#include <ctype.h>
#include <pcap.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// 매크로 상수 선언
#define ETHERNET_HEADER_LEN 14
#define ETHER_TYPE_IPV4 0x0800
#define IPV4_MIN_HEADER_LEN 20
#define TCP_MIN_HEADER_LEN 20
#define TCP_PROTOCOL_NUMBER 6
#define SNAP_LEN 65535
#define DISPLAY_PAYLOAD_MAX 1024

// 이더넷 헤더를 C 구조체로 표현
#pragma pack(push, 1)
typedef struct {
    uint8_t dst_mac[6];
    uint8_t src_mac[6];
    uint16_t ether_type;
} ethernet_header_t;

//IP 헤더 구조체
typedef struct {
    uint8_t version_ihl;
    uint8_t tos;
    uint16_t total_length;
    uint16_t identification;
    uint16_t flags_fragment_offset;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t header_checksum;
    struct in_addr src_ip;
    struct in_addr dst_ip;
} ipv4_header_t;

//tcp 헤더 구조체
typedef struct {
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t seq_number;
    uint32_t ack_number;
    uint8_t data_offset_reserved;
    uint8_t flags;
    uint16_t window_size;
    uint16_t checksum;
    uint16_t urgent_pointer;
} tcp_header_t;
#pragma pack(pop)

//패킷 번호를 세기 위한 구조체 타입 
typedef struct {
    unsigned long long packet_number;
} capture_context_t;

//프로그램 사용법을 출력
static void usage(const char *program_name)
{
    fprintf(stderr, "Usage:\n");
    fprintf(stderr, "  %s <interface>\n", program_name);
    fprintf(stderr, "  %s -r <file.pcap>\n", program_name);
}

//mac 주소 6바이트를 사람이 읽을 수 있는 형태로 출력
static void print_mac(const uint8_t mac[6])
{
    printf("%02x:%02x:%02x:%02x:%02x:%02x",
           mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

// 패킷 안에 우리가 읽으려는 만큼의 바이트가 실제로 남아 있는지 검사하는 안정 장치
// 패킷을 파싱할 때 packet + offset 위치에서 needed 바이트를 읽는다
// 실제 캡처된 패킷 길이가 caplen인데, 이 범위를 넘어서면 위험하기에 이러한 안전장치를 마련해둔다
static int has_bytes(size_t caplen, size_t offset, size_t needed)
{
    return offset <= caplen && needed <= caplen - offset;
}

static size_t min_size(size_t a, size_t b)
{
    return a < b ? a : b;
}


// TCP Payload가 HTTP 메세지처럼 보이는지 간단히 검사하는 함수
static int looks_like_http(const uint8_t *payload, size_t payload_len)
{
    static const char *prefixes[] = {
        "GET ", "POST ", "HEAD ", "PUT ", "DELETE ", "PATCH ",
        "OPTIONS ", "CONNECT ", "TRACE ", "HTTP/"
    };
    size_t i;

    for (i = 0; i < sizeof(prefixes) / sizeof(prefixes[0]); i++) {
        size_t prefix_len = strlen(prefixes[i]);
        if (payload_len >= prefix_len &&
            memcmp(payload, prefixes[i], prefix_len) == 0) {
            return 1;
        }
    }

    return 0;
}

// tcp payload 출력

// const uint8_t *payload : 출력할 데이터 시작 부분
// size_t payload_len : payload 크기
static void print_payload_text(const uint8_t *payload, size_t payload_len)
{
		
    
    // payload가 너무 길 수도 있으니 DISPLAY_PAYLOAD_MAX만큼 출력한다
    size_t display_len = min_size(payload_len, DISPLAY_PAYLOAD_MAX);
    
    
    size_t i;
	
		// tcp가 항상 payload를 가지고 있는 것은 아니다. 따라서 이를 위한 예외 처리를 해준다
    if (payload_len == 0) {
        printf("HTTP Message: <no TCP application data>\n");
        return;
    }
    
		// payload 길이 출력
    printf("HTTP Message / TCP Payload: %zu byte%s",
           payload_len, payload_len == 1 ? "" : "s");
    
    // payload가 http 타입으로 시작하는지 검사
    if (!looks_like_http(payload, payload_len)) {
        printf(" (payload does not look like plain HTTP)");
    }
    
    // payload가 너무 길어서 앞부분만 출력하는 경우를 위한 안내
    if (display_len < payload_len) {
        printf(" (showing first %zu bytes)", display_len);
    }
    printf("\n");


		// 출력 시작
    printf("----- Payload Start -----\n");
    for (i = 0; i < display_len; i++) {
        uint8_t c = payload[i];

        if (c == '\r') {
            printf("\\r");
        } else if (c == '\n') {
            printf("\\n\n");
        } else if (c == '\t') {
            printf("\\t");
        } else if (isprint(c)) {
            putchar((int)c);
        } else {
            putchar('.');
        }
    }
    
    // 출력 불가능한 부분은 . 으로 표시
    // 암호화된 https payload나 이미지 데이터 같은 건 사람이 읽을 수 없기 때문이다.
    // 추후 인증서를 등록해서 https도 읽을 수 있도록 해볼 예정
    if (display_len > 0 && payload[display_len - 1] != '\n') {
        putchar('\n');
    }
    printf("----- Payload End -------\n");
}

//패킷 분석 함수. 이번 과제의 핵심

// 함수 인자 설명
// user : pcap_loop() 에서 넘긴 사용자 데이터인데, 여기서는 패킷 번호라고 한다
// packet_header : 패킷 길이 같은 메타정보
// packet : 실제 패킷 byte 길이
static void analyze_packet(u_char *user,
                           const struct pcap_pkthdr *packet_header,
                           const u_char *packet)
{
		// user로 넘어온 값ㅇ르 다시 capture_context_t * 으로 바꾼다
		// 이렇게 해야 패킷번호를 증가시킬 수 있다고 한다
		// 예시 : context -> packet_number++;
    capture_context_t *context = (capture_context_t *)user;
    
    // 아래 변수들은 이더넷, IP, TCP 헤더 위치와 길이를 계산하기 위해 사용된다
    const ethernet_header_t *eth;
    const ipv4_header_t *ip;
    const tcp_header_t *tcp;
    
    size_t caplen = packet_header->caplen;
    size_t ip_offset = ETHERNET_HEADER_LEN;
    size_t ip_header_len;
    size_t tcp_offset;
    size_t tcp_header_len;
    size_t payload_offset;
    size_t payload_len;
    size_t captured_ip_len;
    size_t valid_ip_len;
    uint16_t ether_type;
    uint16_t ip_total_len;
    uint16_t frag_info;
    uint16_t frag_offset;
    char src_ip[INET_ADDRSTRLEN];
    char dst_ip[INET_ADDRSTRLEN];

    context->packet_number++;

		// 패킷에 이더넷 헤더가 없으면 검사를 종료한다
    if (!has_bytes(caplen, 0, sizeof(ethernet_header_t))) {
        return;
    }

		// 패킷의 시작 부분을 이더넷 헤더로 해석하겠다 라는 뜻
		// packet은 PCAP가 준 바이트 배열의 시작 주소이다
		// 실제로 아래와 같은 느낌이고, packet은 아래 기준 ff를 가르킨다고 한다
		// [ff][aa][bb][cc][dd]...
		// 위에서 ethernet_header_t 구조체를 이와 맞게 선언해놓았었다
		// 즉, packet이라는 주소를 그냥 바이트 주소로 보지 말고, 이더넷 헤더 구조체가 있는 주소로
		// 해석하라는 의미이다
    eth = (const ethernet_header_t *)packet;
    
    // 이더넷 헤더의 타입이 IPv4인지 검사
    // ntohs()는 네트워크 바이트 순서 값을 내 컴퓨터가 읽는 순서로 바꾸는 함수이다
		// 네트워크에서 온 2바이트 값을 내 컴퓨터가 읽기 좋은 숫자 순서로 바꾸는 것
		// 리틀 엔디안과 빅 엔디안 마다 읽는 순서가 다르다
		// 리틀 엔디안 : 0x 08 00 -> 0x 00 08
		// 빅 엔디안 : 0x 08 00 -> 0x 08 00
    ether_type = ntohs(eth->ether_type);
    if (ether_type != ETHER_TYPE_IPV4) {
        return;
    }

		// 패킷에 아이피 헤더가 있는지 검사
		// 위에서 ip_offset을 14로 정의했었다
    if (!has_bytes(caplen, ip_offset, sizeof(ipv4_header_t))) {
        return;
    }
		
		// packet + 14 다음부터 IPv4로 인식
    ip = (const ipv4_header_t *)(packet + ip_offset);
    
    // IP헤더에서 헤더 길이를 꺼내는 코드이다
    // IP 헤더는 Version(4bit) - Header Length(IHL)(4bit).. 로 이루어져 있다
    // 만약 IPv4의 첫 바이트가 0x45라면은...
    // 0x45 -> 0100 0101 -> Version : 0100, IHL : 0101
    // 0100은 IPv4를 의미하고, 0101은 IP헤더 길이를 의미한다
    // 그런데 여기서 IHL의 값 0101(5)는 4바이트 단위가 몇 개 있는지를 의미한다
    // 따라서 IPv4의 헤더 길이는 5 * 4 = 20바이트
    // 따라서 보통 IPv4의 헤더는 0x45로 시작한다고 볼 수 있다
    // 아래 코드에서 ip->version_ihl은 첫 바이트를 의미한다, 즉 0x45
    // 0x0f는 2진수로 0000 1111이다
    // 0x45 & 0x0f == 0100 0101 & 0000 11111 == 0000 0101
    // 즉, 앞의 Version은 버리고 뒤의 IHL만 남는다
    // 위와 동일하게 4바이트 단위이므로 앤드 연산후 나온 값에 4를 곱하면 IHL을 구할 수 있다.
    ip_header_len = (size_t)(ip->version_ihl & 0x0f) * 4;
    
    // 헤더 길이가 20바이트보다 작거나 ipv4가 아니면 버린다
    // 여기서 version_ihl은 위에서 0100 0101이라고 했는데
    // 오른족으로 4칸 밀기(>> 4) 를 시전하면 0000 0100이 되므로, 4가 된다
    // 만약 밀어서 나온 값이 4가 아니면 ipv4가 아니므로 버린다는 뜻.
    if ((ip->version_ihl >> 4) != 4 || ip_header_len < IPV4_MIN_HEADER_LEN) {
        return;
    }
	
    if (!has_bytes(caplen, ip_offset, ip_header_len)) {
        return;
    }
		
		// IP 헤더의 Protocol값이 6이 아니면 버린다(TCP)
    if (ip->protocol != TCP_PROTOCOL_NUMBER) {
        return;
    }
		
		// IP Fragment 처리이다
		// IP 패킷은 분할이 가능하고, 이를 IP 헤더에서 0 | DF | MF 로 표현한다
		// 각각 dont fragment, more fragment 라는 뜻
		// 말 그대로 분할하지 마라, 뒤에 분할된 패킷이 더 있다
		// 그리고 뒤에 나오는 fragment offset 필드로 패킷의 순서를 구별한다
		// 만약 0이 아니라면 두번째 패킷이라는 뜻인데, 즉 첫번째 패킷만 분석을 진행한다
		// 공부할 때는 이렇게 간단하게 하고, 추후 생성형 AI를 활용하여  
		// 재조합 + 인증서(https) 기능까지구현할 얘정
    frag_info = ntohs(ip->flags_fragment_offset);
    frag_offset = frag_info & 0x1fff;
    if (frag_offset != 0) {
        return;
    }
		
		// ip header에 적힌 전체 ip 패킷의 길이를 가져온다
    ip_total_len = ntohs(ip->total_length);
    
    // ip header의 길이보다 ip 패킷의 전체 길이가 작으면 종료
    if (ip_total_len < ip_header_len) {
        return;
    }

    captured_ip_len = caplen - ip_offset;
    valid_ip_len = min_size((size_t)ip_total_len, captured_ip_len);

		// tcp 위치를 계사한다
		// tcp는 이더넷 헤더 + 아이피 헤더 다음에 위치한다
    tcp_offset = ip_offset + ip_header_len;
    if (!has_bytes(caplen, tcp_offset, sizeof(tcp_header_t))) {
        return;
    }

    tcp = (const tcp_header_t *)(packet + tcp_offset);
    
    // tcp 헤더 줄 구하기
    tcp_header_len = (size_t)((tcp->data_offset_reserved >> 4) & 0x0f) * 4;
    if (tcp_header_len < TCP_MIN_HEADER_LEN) {
        return;
    }
	
    if (ip_header_len + tcp_header_len > valid_ip_len ||
        !has_bytes(caplen, tcp_offset, tcp_header_len)) {
        return;
    }
		
		// payload 위치 계산
		// payload는 tcp header 뒤에 위치한다
		// payload = ip 전체 길이 - ip hader - tcp header
    payload_offset = tcp_offset + tcp_header_len;
    payload_len = valid_ip_len - ip_header_len - tcp_header_len;
		
		// 아래 코드는 IP 주소를 문자열로 변환하는 코드이다
		// ip 주소는 내부적으로 32bit 숫자인데, 이를 inet_ntop()이 우리가 보기 좋게 바꿔준다
    if (inet_ntop(AF_INET, &ip->src_ip, src_ip, sizeof(src_ip)) == NULL) {
        snprintf(src_ip, sizeof(src_ip), "<invalid>");
    }
    if (inet_ntop(AF_INET, &ip->dst_ip, dst_ip, sizeof(dst_ip)) == NULL) {
        snprintf(dst_ip, sizeof(dst_ip), "<invalid>");
    }

    printf("\n============================================================\n");
    printf("Packet #%llu\n", context->packet_number);
    printf("Captured Length: %u bytes, Original Length: %u bytes\n",
           packet_header->caplen, packet_header->len);

    printf("[Ethernet Header]\n");
    printf("  src mac: ");
    print_mac(eth->src_mac);
    printf("\n");
    printf("  dst mac: ");
    print_mac(eth->dst_mac);
    printf("\n");

    printf("[IP Header]\n");
    printf("  src ip: %s\n", src_ip);
    printf("  dst ip: %s\n", dst_ip);
    printf("  ip_header_len: %zu bytes\n", ip_header_len);

    printf("[TCP Header]\n");
    printf("  src port: %u\n", ntohs(tcp->src_port));
    printf("  dst port: %u\n", ntohs(tcp->dst_port));
    printf("  tcp_header_len: %zu bytes\n", tcp_header_len);

    printf("[HTTP Message]\n");
    print_payload_text(packet + payload_offset, payload_len);
}

// 사용자가 준 실행 인자를 보고 PCAP handle를 여는 함수
static pcap_t *open_capture_handle(int argc, char *argv[], char *errbuf)
{
    pcap_t *handle;
		
		// 파일 읽기 모드
		// 인자가 3개이고, 두 번째 인자가 -r이면 파일 분석 모드로 들어간다
    if (argc == 3 && strcmp(argv[1], "-r") == 0) {
		    // argv[2]에 들어있는 pcap 파일 열기
        handle = pcap_open_offline(argv[2], errbuf);
        // 실패하면..
        if (handle == NULL) {
            fprintf(stderr, "pcap_open_offline failed: %s\n", errbuf);
        }
        return handle;
    }
		
		// 실시간 캡처 모드
		// 인자가 2개이면 인터페이스 이름 하나를 받은 것으로 본다
    if (argc == 2) { 
        handle = pcap_open_live(argv[1], SNAP_LEN, 1, 1000, errbuf);
        if (handle == NULL) {
            fprintf(stderr, "pcap_open_live failed: %s\n", errbuf);
        }
        return handle;
    }

    usage(argv[0]);
    return NULL;
}

// 메인 함수
int main(int argc, char *argv[])
{
		// 패킷 캡처를 대표하는 핸들
    pcap_t *handle;
    
    // libpcap 에러 메세지를 담을 버퍼이다
    char errbuf[PCAP_ERRBUF_SIZE];
    
    // 컴파일된 BPF 필터가 저장될 구조체
    struct bpf_program fp;
    
    // TCP 패킷만 받기 위한 필터 문자열
    const char filter_exp[] = "tcp";
    
    // 팻킷 넘버
    capture_context_t context = {0};
    int datalink;

		// capture handle 열기
    handle = open_capture_handle(argc, argv, errbuf);
    if (handle == NULL) {
        return EXIT_FAILURE;
    }
		
		// 이더넷인지 확인한다
		// 우리는 [ethernet][ip][tcp][payload]로 가정하고 분석하는 코드이기 때문에
		// 이 형식과 안 맞으면 에러가 걸린다..
    datalink = pcap_datalink(handle);
    if (datalink != DLT_EN10MB) {
        fprintf(stderr, "Unsupported datalink type: %s\n",
                pcap_datalink_val_to_name(datalink));
        fprintf(stderr, "This assignment parser expects Ethernet frames.\n");
        pcap_close(handle);
        return EXIT_FAILURE;
    }

		// BPF 필터 컴파일
		// tcp라는 문자열 필터를 libpcap이 사용할 수 있는 내부 필터 코드로 바꾼다
    if (pcap_compile(handle, &fp, filter_exp, 1, PCAP_NETMASK_UNKNOWN) == -1) 
    {
        fprintf(stderr, "pcap_compile failed: %s\n", pcap_geterr(handle));
        pcap_close(handle);
        return EXIT_FAILURE;
    }
    
		// BPF 필터 적용
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "pcap_setfilter failed: %s\n", pcap_geterr(handle));
        pcap_freecode(&fp);
        pcap_close(handle);
        return EXIT_FAILURE;
    }

    printf("PCAP Programming assignment sniffer started.\n");
    printf("BPF filter: %s\n", filter_exp);
    printf("Press Ctrl+C to stop live capture.\n");
		
		// 캡처 시작
		// handle : 캡처 대상
		// -1 : 무한 처리
		// analyze_packet : 패킷이 들어올 때마다 실행할 함수
		// &context : 콜백에 같이 넘길 사용자 데이터
    if (pcap_loop(handle, -1, analyze_packet, (u_char *)&context) == -1) {
        fprintf(stderr, "pcap_loop failed: %s\n", pcap_geterr(handle));
        pcap_freecode(&fp);
        pcap_close(handle);
        return EXIT_FAILURE;
    }

		// 할당된 메모리 해제
    pcap_freecode(&fp);
    pcap_close(handle);
    return EXIT_SUCCESS;
}














