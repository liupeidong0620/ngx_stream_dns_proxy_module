#ifndef NGX_STREAM_DNS_PROXY_MODULE_H
#define NGX_STREAM_DNS_PROXY_MODULE_H

#include "ngx_dns_decode_packet.h"

typedef struct {
    ngx_chain_t  *from_upstream;
    ngx_chain_t  *from_downstream;
    ngx_dns_msg_t question_msg;
    ngx_dns_msg_t answer_msg;
} ngx_stream_dns_proxy_ctx_t;

typedef struct {
    ngx_msec_t                       connect_timeout;
    ngx_msec_t                       timeout;
    ngx_msec_t                       next_upstream_timeout;
    size_t                           buffer_size;
    ngx_uint_t                       next_upstream_tries;
    ngx_flag_t                       next_upstream;

    int                              type;

    ngx_flag_t                       decode_packet_enable;

    ngx_stream_upstream_srv_conf_t  *upstream;

} ngx_stream_dns_proxy_srv_conf_t;

extern ngx_module_t ngx_stream_dns_proxy_module;

#endif /* NGX_STREAM_DNS_MODULE_H */
