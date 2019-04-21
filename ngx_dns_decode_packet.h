#ifndef NGX_DNS_DECODE_PACKET_H
#define NGX_DNS_DECODE_PACKET_H

typedef struct {
    uint16_t    id;
    uint8_t     response;
    int         opcode;
    uint8_t     authoritative;
    uint8_t     truncated;
    uint8_t     recursionDesired;
    uint8_t     recursionAvailable;
    uint8_t     zero;
    uint8_t     authenticatedData;
    uint8_t     checkingDisabled;
    int         rcode;
} ngx_dns_msghdr_t;

typedef struct {
    uint16_t id;
    uint16_t flags;
    uint16_t question;
    uint16_t answer;
    uint16_t authority;
    uint16_t additional;
} ngx_dns_header_t;

typedef struct {
    ngx_str_t   name;     // domain-name
    uint16_t    rtype;
    uint16_t    rclass;
    uint32_t    rttl;
    uint16_t    rdlength;
    void        *rdata;
} ngx_dns_rr_t;

typedef struct {
    ngx_str_t name;
    uint16_t qtype;
    uint16_t qclass;
} ngx_dns_question_t;

typedef struct {
    ngx_dns_header_t hdr;
    ngx_list_t *question;
    ngx_list_t *answer;
    ngx_list_t *au; // authority rrs
    ngx_list_t *ad; // additional rrs
} ngx_dns_msg_t;

typedef struct {
    ngx_str_t ns;
    ngx_str_t mbox;
    uint32_t serial;
    uint32_t refresh;
    uint32_t retry;
    uint32_t expire;
    uint32_t minttl;
} ngx_dns_soa_t;

typedef struct {
    uint16_t preference;
    ngx_str_t mx;
} ngx_dns_mx_t;

void
ngx_stream_parse_dns_package(ngx_stream_session_t *s, ngx_chain_t *in,
        ngx_uint_t from_upstream);

#endif /* NGX_STREAM_DNS_MODULE_H */
