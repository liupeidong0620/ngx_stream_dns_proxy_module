#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_stream.h>

#include "ngx_stream_dns_proxy_module.h"
#include "ngx_dns_type.h"

#define QUESTION_RECORD 1
#define RR_RECORD 2

/* init the table for valid chars */
static u_char valid_char[256] = {
    ['0'] = 1, ['1'] = 1, ['2'] = 1, ['3'] = 1, ['4'] = 1, ['5'] = 1, ['6'] = 1, ['7'] = 1, ['8'] = 1, ['9'] = 1,

    ['a'] = 1, ['b'] = 1, ['c'] = 1,['d'] = 1,['e'] = 1,['f'] = 1,['g'] = 1,['h'] = 1,['i'] = 1,['j'] = 1,['k'] = 1,['l'] = 1,['m'] = 1,
    ['n'] = 1,['o'] = 1,['p'] = 1,['q'] = 1,['r'] = 1,['s'] = 1,['t'] = 1,['u'] = 1,['v'] = 1,['w'] = 1,['x'] = 1,['y'] = 1, ['z'] = 1,

    ['A'] = 1, ['B'] = 1, ['C'] = 1,['D'] = 1,['E'] = 1,['F'] = 1,['G'] = 1,['H'] = 1,['I'] = 1,['J'] = 1,['K'] = 1,['L'] = 1,['M'] = 1,
    ['N'] = 1,['O'] = 1,['P'] = 1,['Q'] = 1,['R'] = 1,['S'] = 1,['T'] = 1,['U'] = 1,['V'] = 1,['W'] = 1,['X'] = 1,['Y'] = 1, ['Z'] = 1,

    ['-'] = 1,
};

static int
ngx_dns_get_objname(ngx_pool_t *pool, u_char *packet, uint16_t packet_len,
        uint16_t index, ngx_str_t *name);

static int
ngx_dns_decode_header(u_char *packet, uint16_t packet_len,
        ngx_dns_header_t *hdr);

static int
ngx_dns_read_record(ngx_pool_t *pool, ngx_int_t type,
        u_char *packet, uint16_t packet_len, uint16_t index, void **rr);

static int
ngx_dns_decode_packet(ngx_pool_t *pool, u_char *packet, 
        uint16_t packet_len, ngx_dns_msg_t *msg);

static int
ngx_dns_get_objname(ngx_pool_t *pool, u_char *packet, uint16_t packet_len,
        uint16_t index, ngx_str_t *name)
{
    ngx_int_t i = index;
    ngx_int_t j = 0;
    ngx_int_t depth = 0;
    ngx_int_t compressed = 0;
    u_char c;
    u_char dest[512] = {};
    ngx_int_t destsize = sizeof(dest);

    if(packet == NULL || name == NULL) {
        return -1;
    }

    /* we refuse to try to decode anything in the header or after the packet */
    if (index < PACKET_DATABEGIN || i >= packet_len) return(-1);

    while ((c = packet[i++]) != '\0')
    {
        if (i >= packet_len) return (-1);

        /* check if it is a pointer */
        if ((c & 0xc0) == 0xc0)
        {
            /* check that next byte is readable */
            if (i >= packet_len) return (-1); 

            /* Avoid circular pointers. */
            depth++;
            if ((depth >= packet_len)) return(-1);

            /* we store the first location */
            if (!compressed) compressed = i+1;

            /* check that the pointer points within limits */
            if ((i = ((c & 0x3f) << 8) + packet[i]) >= packet_len) return(-1);
            continue;
        }
        else if (c < 64)
        {
            /* check that label length don't cross any borders */
            if ( ((j + c + 1) >= destsize)  || ((i + c) >= packet_len)) return(-1);

            while (c--)
            {
                if (valid_char[packet[i]])
                    dest[j++] = packet[i++];
                else
                    return(-1);
            }
            dest[j++] = '.';
        }
        else
            return(-1); /* a label cannot be longer than 63 */
    }

    if (--j >= (destsize) ) return(-1); /* we need space for '\0' */
    dest[j] = '\0';

    name->data = ngx_palloc(pool, j);
    if(name->data == NULL) {
        return (-1);
    }
    name->len = j;
    ngx_memcpy(name->data, dest, j);

    /* if we used compression, return the location from the first ptr */
    return (compressed ? compressed : i);
}

static int
ngx_dns_decode_header(u_char *packet, uint16_t packet_len,
        ngx_dns_header_t *hdr)
{
    uint16_t *p = NULL;

    if(packet == NULL || hdr == NULL) {
        return -1;
    }

    if(PACKET_DATABEGIN > packet_len) {
        return -1;
    }

    p = (uint16_t *) packet;

    hdr->id         = ntohs(p[0]);
    hdr->flags      = ntohs(p[1]);
    hdr->question   = ntohs(p[2]);
    hdr->answer     = ntohs(p[3]);
    hdr->authority  = ntohs(p[4]);
    hdr->additional = ntohs(p[5]);

    return 0;
}

static int
ngx_dns_read_record(ngx_pool_t *pool, ngx_int_t type,
        u_char *packet, uint16_t packet_len, uint16_t index, void **rr)
{
    int i;
    ngx_dns_question_t **dns_question = NULL;
    ngx_dns_rr_t **dns_rr = NULL;
    ngx_str_t name;

    if(pool == NULL || packet == NULL || rr == NULL) {
        return -1;
    }

    i = ngx_dns_get_objname(pool, packet, packet_len, index, &name);


    if((i < 0) || (i+4 > packet_len)) return -1;

    if(type == QUESTION_RECORD) {
        dns_question = (ngx_dns_question_t **)rr;
        (*dns_question)->name = name;
        (*dns_question)->qtype  = ntohs(*((uint16_t *)(packet + i)));
        (*dns_question)->qclass = ntohs(*((uint16_t *)(packet + i + 2)));

        return i + 4;
    } else {
        dns_rr = (ngx_dns_rr_t **) rr;
        (*dns_rr)->name = name;
        (*dns_rr)->rtype  = ntohs(*((uint16_t *)(packet + i)));
        (*dns_rr)->rclass = ntohs(*((uint16_t *)(packet + i + 2)));
    }
    
    i += 4;

    if(i + 6 > packet_len) return -1;

    (*dns_rr)->rttl     = ntohl(*((uint32_t*)(packet + i)));
    (*dns_rr)->rdlength = ntohs(*((uint16_t*)(packet + i + 4)));

    i += 6;

    if(i + (*dns_rr)->rdlength > packet_len) return -1;
    if((*dns_rr)->rtype == TypeCNAME) {
        i = ngx_dns_get_objname(pool, packet, packet_len, i, &((*dns_rr)->rdata));
    } else {
        (*dns_rr)->rdata.data = ngx_palloc(pool, (*dns_rr)->rdlength);
        (*dns_rr)->rdata.len = (*dns_rr)->rdlength;
        ngx_memcpy((*dns_rr)->rdata.data, packet + i, (*dns_rr)->rdata.len);
        i += (*dns_rr)->rdlength;
    }

    return i;
}

static int
ngx_dns_decode_packet(ngx_pool_t *pool, u_char *packet, 
        uint16_t packet_len, ngx_dns_msg_t *msg)
{
    int i, index;
    int ret = 0;
    ngx_dns_question_t *dns_question = NULL;
    ngx_dns_rr_t *dns_rr = NULL;

    if (pool == NULL || packet == NULL || msg == NULL) {
        return -1;
    }

    if (packet_len <= 12) {
        return -1;
    }

    // parse dns header
    if((ret = ngx_dns_decode_header(packet, packet_len, &(msg->hdr))) < 0) {
        return -1;
    }

    index = PACKET_DATABEGIN;
    // parse dns question
    for (i = 0; i < msg->hdr.question; i ++) {
        dns_question = (ngx_dns_question_t *)ngx_list_push(msg->question);
        if (dns_question == NULL) {
            return -1;
        }
        index = ngx_dns_read_record(pool, QUESTION_RECORD, 
                packet, packet_len, index, (void **)&dns_question);
        if(index < 0) {
            return -1;
        }
    }

    if(GET_QR(msg->hdr.flags) == 0) {
        return 0;
    }
    
    // parse dns answer rr
    for (i = 0; i < msg->hdr.answer; i++) {
        dns_rr = (ngx_dns_rr_t *)ngx_list_push(msg->answer);
        if (dns_rr == NULL) {
            return -1;
        }
        index = ngx_dns_read_record(pool, RR_RECORD,
                packet, packet_len, index, (void **)&dns_rr);
        if (index < 0) {
            return -1;
        }
    }

    return 0;
}

void
ngx_stream_parse_dns_package(ngx_stream_session_t *s, ngx_chain_t *in,
        ngx_uint_t from_upstream)
{
    ngx_connection_t                *c, *pc;
    ngx_stream_dns_proxy_ctx_t      *ctx;
    ngx_stream_upstream_t           *u;
    uint16_t packet_len = 0;
    //int ret = 0;

    if (in == NULL || s == NULL) {
        return;
    }

    if(in->buf == NULL || in->buf->last <= in->buf->pos) {
        return;
    }
    packet_len = in->buf->last - in->buf->pos;
    if(packet_len <= PACKET_DATABEGIN) {
        return;
    }

    ctx = ngx_stream_get_module_ctx(s, ngx_stream_dns_proxy_module);
    if(ctx == NULL) {
        return ;
    }

    c = s->connection;
    u = s->upstream;
    pc = u->peer.connection;

    if (from_upstream) {
        if(c->type == SOCK_DGRAM) {
            ngx_dns_decode_packet(c->pool, in->buf->pos, 
                    packet_len, &(ctx->answer_msg));
            /*ngx_log_debug3(NGX_LOG_DEBUG_STREAM, c->log, 0,
                    "ngx_stream_parse_dns_package(): from_upstram: %d, SOCK_DGRAM, packet_len: %d, ret: %d", 
                    from_upstream, in->buf->last - in->buf->pos, ret);*/
        } else {
            ngx_dns_decode_packet(c->pool, in->buf->pos + 2, 
                    packet_len - 2, &(ctx->answer_msg));
            /*ngx_log_debug3(NGX_LOG_DEBUG_STREAM, c->log, 0,
                    "ngx_stream_parse_dns_package(): from_upstram: %d, SOCK_STREAM, packet_len: %d, ret: %d", 
                    from_upstream, in->buf->last - in->buf->pos, ret);*/
        }
    } else {
        if(pc->type == SOCK_DGRAM) {
            ngx_dns_decode_packet(c->pool, in->buf->pos, 
                    packet_len, &(ctx->question_msg));
            /*ngx_log_debug3(NGX_LOG_DEBUG_STREAM, c->log, 0,
                    "ngx_stream_parse_dns_package(): from_upstram: %d, SOCK_DGRAM, packet_len: %d, ret: %d", 
                    from_upstream, in->buf->last - in->buf->pos, ret);*/
        } else {
            ngx_dns_decode_packet(c->pool, in->buf->pos + 2, 
                    packet_len - 2, &(ctx->question_msg));
            /*ngx_log_debug3(NGX_LOG_DEBUG_STREAM, c->log, 0,
                    "ngx_stream_parse_dns_package(): from_upstram: %d, SOCK_STREAM, packet_len: %d, ret: %d", 
                    from_upstream, in->buf->last - in->buf->pos, ret);*/
        }
    }
}

