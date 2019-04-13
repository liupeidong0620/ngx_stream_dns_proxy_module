/*
 * Copyright (C) lpd
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_stream.h>

#include "ngx_stream_dns_proxy_module.h"
#include "ngx_dns_type.h"

static ngx_stream_filter_pt ngx_stream_next_filter;

static void ngx_stream_dns_proxy_handler(ngx_stream_session_t *s);

static void ngx_stream_dns_proxy_connect(ngx_stream_session_t *s);

static void ngx_stream_dns_proxy_init_upstream(ngx_stream_session_t *s);

static void ngx_stream_dns_proxy_upstream_handler(ngx_event_t *ev);

static void ngx_stream_dns_proxy_downstream_handler(ngx_event_t *ev);

static void ngx_stream_dns_proxy_process_connection(ngx_event_t *ev,
    ngx_uint_t from_upstream);

static void ngx_stream_dns_proxy_connect_handler(ngx_event_t *ev);

static ngx_int_t ngx_stream_dns_proxy_test_connect(ngx_connection_t *c);

static void ngx_stream_dns_proxy_process(ngx_stream_session_t *s,
    ngx_uint_t from_upstream, ngx_uint_t do_write);

static ngx_int_t ngx_stream_dns_proxy_test_finalize(ngx_stream_session_t *s,
    ngx_uint_t from_upstream);

static void ngx_stream_dns_proxy_next_upstream(ngx_stream_session_t *s);

static void ngx_stream_dns_proxy_finalize(ngx_stream_session_t *s, ngx_uint_t rc);

static u_char *ngx_stream_dns_proxy_log_error(ngx_log_t *log, u_char *buf,
    size_t len);

static void *ngx_stream_dns_proxy_create_srv_conf(ngx_conf_t *cf);

static char *ngx_stream_dns_proxy_merge_srv_conf(ngx_conf_t *cf, void *parent,
    void *child);

static char *ngx_stream_dns_proxy_pass(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);

/******************** dns write filter ***************************/
static ngx_int_t
ngx_stream_dns_write_filter(ngx_stream_session_t *s,
    ngx_chain_t *in, ngx_uint_t from_upstream);

static ngx_int_t
ngx_stream_dns_write_filter_init(ngx_conf_t *cf);

static ngx_int_t
ngx_stream_variable_dns_answer_context(ngx_stream_session_t *s,
     ngx_stream_variable_value_t *v, uintptr_t data);

static ngx_int_t
ngx_stream_variable_dns_question_context(ngx_stream_session_t *s,
     ngx_stream_variable_value_t *v, uintptr_t data);

static ngx_int_t
ngx_stream_dns_add_vars(ngx_conf_t* cf);

static ngx_stream_variable_t  ngx_stream_dns_variables[] = {

    { ngx_string("dns_answer_context"), NULL,
      ngx_stream_variable_dns_answer_context, 0,
      0, 0 },

    { ngx_string("dns_question_context"), NULL,
      ngx_stream_variable_dns_question_context, 0,
      0, 0 },

    { ngx_null_string, NULL, NULL, 0, 0, 0 }
};

static ngx_command_t  ngx_stream_dns_proxy_commands[] = {

    { ngx_string("dns_proxy_pass"),
      NGX_STREAM_SRV_CONF|NGX_CONF_TAKE12,
      ngx_stream_dns_proxy_pass,
      NGX_STREAM_SRV_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("dns_proxy_connect_timeout"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_dns_proxy_srv_conf_t, connect_timeout),
      NULL },

    { ngx_string("dns_proxy_timeout"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_dns_proxy_srv_conf_t, timeout),
      NULL },

    /*{ ngx_string("dns_proxy_buffer_size"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_dns_proxy_srv_conf_t, buffer_size),
      NULL },*/

    /*{ ngx_string("dns_proxy_next_upstream_timeout"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_dns_proxy_srv_conf_t, next_upstream_timeout),
      NULL },*/

      ngx_null_command
};

static ngx_stream_module_t  ngx_stream_dns_proxy_module_ctx = {
    ngx_stream_dns_add_vars,                    /* preconfiguration */
    ngx_stream_dns_write_filter_init,          /* postconfiguration */

    NULL,                                       /* create main configuration */
    NULL,                                       /* init main configuration */

    ngx_stream_dns_proxy_create_srv_conf,       /* create server configuration */
    ngx_stream_dns_proxy_merge_srv_conf         /* merge server configuration */
};


ngx_module_t  ngx_stream_dns_proxy_module = {
    NGX_MODULE_V1,
    &ngx_stream_dns_proxy_module_ctx,       /* module context */
    ngx_stream_dns_proxy_commands,          /* module directives */
    NGX_STREAM_MODULE,                      /* module type */
    NULL,                                   /* init master */
    NULL,                                   /* init module */
    NULL,                                   /* init process */
    NULL,                                   /* init thread */
    NULL,                                   /* exit thread */
    NULL,                                   /* exit process */
    NULL,                                   /* exit master */
    NGX_MODULE_V1_PADDING
};

static void
ngx_stream_dns_proxy_handler(ngx_stream_session_t *s)
{
    u_char                           *p;
    ngx_connection_t                 *c;
    ngx_stream_upstream_t            *u;
    ngx_stream_dns_proxy_srv_conf_t  *pscf;
    ngx_stream_upstream_srv_conf_t   *uscf;// **uscfp;
    ngx_stream_dns_proxy_ctx_t   *ctx;

    c = s->connection;

    pscf = ngx_stream_get_module_srv_conf(s, ngx_stream_dns_proxy_module);

    u = ngx_pcalloc(c->pool, sizeof(ngx_stream_upstream_t));
    if (u == NULL) {
        ngx_stream_dns_proxy_finalize(s, NGX_STREAM_INTERNAL_SERVER_ERROR);
        return;
    }

    s->upstream = u;

    s->log_handler = ngx_stream_dns_proxy_log_error;

    u->requests = 1;

    u->peer.log = c->log;
    u->peer.log_error = NGX_ERROR_ERR;

    if (pscf->type != NGX_CONF_UNSET) {
        u->peer.type = pscf->type;
    } else {
        u->peer.type = c->type;
    }

    ctx = ngx_stream_get_module_ctx(s, ngx_stream_dns_proxy_module);
    if (ctx == NULL) {
        ctx = ngx_pcalloc(c->pool,
                sizeof(ngx_stream_dns_proxy_ctx_t));
        if (ctx == NULL) {
            return ;
        }
        ctx->from_upstream = NULL;
        ctx->from_downstream = NULL;

        ctx->question_msg.question = ngx_list_create(c->pool, 1, 
                sizeof(ngx_dns_question_t));
        ctx->question_msg.answer = ngx_list_create(c->pool, 3, 
                sizeof(ngx_dns_rr_t));
        ctx->answer_msg.question = ngx_list_create(c->pool, 1, 
                sizeof(ngx_dns_question_t));
        ctx->answer_msg.answer = ngx_list_create(c->pool, 3, 
                sizeof(ngx_dns_rr_t));

        ngx_stream_set_ctx(s, ctx, ngx_stream_dns_proxy_module);
    }

    u->start_sec = ngx_time();

    c->write->handler = ngx_stream_dns_proxy_downstream_handler;
    c->read->handler = ngx_stream_dns_proxy_downstream_handler;

    s->upstream_states = ngx_array_create(c->pool, 1,
                                          sizeof(ngx_stream_upstream_state_t));
    if (s->upstream_states == NULL) {
        ngx_stream_dns_proxy_finalize(s, NGX_STREAM_INTERNAL_SERVER_ERROR);
        return;
    }

    p = ngx_pnalloc(c->pool, pscf->buffer_size);
    if (p == NULL) {
        ngx_stream_dns_proxy_finalize(s, NGX_STREAM_INTERNAL_SERVER_ERROR);
        return;
    }

    u->downstream_buf.start = p;
    u->downstream_buf.end = p + pscf->buffer_size;
    u->downstream_buf.pos = p;
    u->downstream_buf.last = p;

    if (c->read->ready) {
        ngx_post_event(c->read, &ngx_posted_events);
    }

    uscf = pscf->upstream;

    if (uscf == NULL) {
        ngx_log_error(NGX_LOG_ALERT, c->log, 0, "no upstream configuration");
        ngx_stream_dns_proxy_finalize(s, NGX_STREAM_INTERNAL_SERVER_ERROR);
        return;
    }

    u->upstream = uscf;

    if (uscf->peer.init(s, uscf) != NGX_OK) {
        ngx_stream_dns_proxy_finalize(s, NGX_STREAM_INTERNAL_SERVER_ERROR);
        return;
    }

    u->peer.start_time = ngx_current_msec;

    if (pscf->next_upstream_tries
        && u->peer.tries > pscf->next_upstream_tries)
    {
        u->peer.tries = pscf->next_upstream_tries;
    }

    ngx_stream_dns_proxy_connect(s);
}

static void
ngx_stream_dns_proxy_connect(ngx_stream_session_t *s)
{
    ngx_int_t                     rc;
    ngx_connection_t             *c, *pc;
    ngx_stream_upstream_t        *u;
    ngx_stream_dns_proxy_srv_conf_t  *pscf;

    c = s->connection;

    c->log->action = "connecting to upstream";

    pscf = ngx_stream_get_module_srv_conf(s, ngx_stream_dns_proxy_module);

    u = s->upstream;

    u->connected = 0;
    //u->proxy_protocol = pscf->proxy_protocol;

   // if (u->state) {
    //    u->state->response_time = ngx_current_msec - u->start_time;
   // }

    u->state = ngx_array_push(s->upstream_states);
    if (u->state == NULL) {
        ngx_stream_dns_proxy_finalize(s, NGX_STREAM_INTERNAL_SERVER_ERROR);
        return;
    }

    ngx_memzero(u->state, sizeof(ngx_stream_upstream_state_t));

    u->state->connect_time = (ngx_msec_t) -1;
    u->state->first_byte_time = (ngx_msec_t) -1;

    u->state->response_time = (ngx_msec_t) -1;

    rc = ngx_event_connect_peer(&u->peer);

    ngx_log_debug1(NGX_LOG_DEBUG_STREAM, c->log, 0, "proxy connect: %i", rc);

    if (rc == NGX_ERROR) {
        ngx_stream_dns_proxy_finalize(s, NGX_STREAM_INTERNAL_SERVER_ERROR);
        return;
    }

    u->state->peer = u->peer.name;

    // 所有上游都busy
    if (rc == NGX_BUSY) {
        ngx_log_error(NGX_LOG_ERR, c->log, 0, "no live upstreams");
        ngx_stream_dns_proxy_finalize(s, NGX_STREAM_BAD_GATEWAY);
        return;
    }

    if (rc == NGX_DECLINED) {
        ngx_stream_dns_proxy_next_upstream(s);
        return;
    }

    pc = u->peer.connection;

    pc->data = s;
    pc->log = c->log;
    pc->pool = c->pool;
    pc->read->log = c->log;
    pc->write->log = c->log;

    if (rc != NGX_AGAIN) {
        ngx_stream_dns_proxy_init_upstream(s);
        return;
    }

    pc->read->handler = ngx_stream_dns_proxy_connect_handler;
    pc->write->handler = ngx_stream_dns_proxy_connect_handler;

    ngx_add_timer(pc->write, pscf->connect_timeout);
}


static void
ngx_stream_dns_proxy_init_upstream(ngx_stream_session_t *s)
{
    u_char                       *p;
    ngx_chain_t                  *cl;
    ngx_connection_t             *c, *pc;
    ngx_log_handler_pt            handler;
    ngx_stream_upstream_t        *u;
    ngx_stream_core_srv_conf_t   *cscf;
    ngx_stream_dns_proxy_srv_conf_t  *pscf;
    uint16_t tcp_head_len = 0, proxy_flag = 0, buf_len = 0, temp_buf_len;
    ngx_uint_t do_write = 1;
    ngx_buf_t                    *b;
    ngx_stream_dns_proxy_ctx_t   *ctx;

    u = s->upstream;

    pc = u->peer.connection;

    cscf = ngx_stream_get_module_srv_conf(s, ngx_stream_core_module);

    if (pc->type == SOCK_STREAM
        && cscf->tcp_nodelay
        && ngx_tcp_nodelay(pc) != NGX_OK)
    {
        ngx_stream_dns_proxy_next_upstream(s);
        return;
    }

    pscf = ngx_stream_get_module_srv_conf(s, ngx_stream_dns_proxy_module);

    c = s->connection;

    if (c->log->log_level >= NGX_LOG_INFO) {
        ngx_str_t  str;
        u_char     addr[NGX_SOCKADDR_STRLEN];

        str.len = NGX_SOCKADDR_STRLEN;
        str.data = addr;

        if (ngx_connection_local_sockaddr(pc, &str, 1) == NGX_OK) {
            handler = c->log->handler;
            c->log->handler = NULL;

            ngx_log_error(NGX_LOG_INFO, c->log, 0,
                          "%sproxy %V connected to %V",
                          pc->type == SOCK_DGRAM ? "udp " : "",
                          &str, u->peer.name);

            c->log->handler = handler;
        }
    }

    if (u->peer.notify) {
        u->peer.notify(&u->peer, u->peer.data,
                       NGX_STREAM_UPSTREAM_NOTIFY_CONNECT);
    }

    if (u->upstream_buf.start == NULL) {

        p = ngx_pnalloc(c->pool, pscf->buffer_size);
        if (p == NULL) {
            ngx_stream_dns_proxy_finalize(s, NGX_STREAM_INTERNAL_SERVER_ERROR);
            return;
        }

        u->upstream_buf.start = p;
        u->upstream_buf.end = p + pscf->buffer_size;
        u->upstream_buf.pos = p;
        u->upstream_buf.last = p;
    }

    if (c->buffer && c->buffer->pos < c->buffer->last) {
        ngx_log_debug1(NGX_LOG_DEBUG_STREAM, c->log, 0,
                       "stream proxy add preread buffer: %uz",
                       c->buffer->last - c->buffer->pos);

        cl = ngx_chain_get_free_buf(c->pool, &u->free);
        if (cl == NULL) {
            ngx_stream_dns_proxy_finalize(s, NGX_STREAM_INTERNAL_SERVER_ERROR);
            return;
        }

        if (pscf->type != NGX_CONF_UNSET &&
                c->type != pscf->type) {
            proxy_flag = 1;
        } else {
            proxy_flag = 0;
        }

        ctx = ngx_stream_get_module_ctx(s, ngx_stream_dns_proxy_module);
        buf_len = c->buffer->last - c->buffer->pos;
        if (c->type == SOCK_STREAM) {
            tcp_head_len = ntohs(*((uint16_t*)c->buffer->pos));
            if (buf_len <= 2 || tcp_head_len != buf_len - 2) {
                do_write = 0;
                b = &u->downstream_buf;
                ngx_memcpy(b->last, c->buffer->pos, buf_len);
                cl->buf->pos = b->last;
                cl->buf->last = b->last + buf_len;
                b->last = b->last + buf_len;
                ctx->from_downstream = cl;
                goto done;
            } else {
                if (proxy_flag) {
                    c->buffer->pos += 2;
                }
                *cl->buf = *c->buffer;
            }
        }

        if (c->type == SOCK_DGRAM) {
            if (proxy_flag) {
                b = &u->downstream_buf;
                temp_buf_len = htons(buf_len);
                ngx_memcpy(b->last, (char*)&temp_buf_len, 2);
                ngx_memcpy(b->last + 2, c->buffer->pos, buf_len);
                cl->buf->pos = b->last;
                cl->buf->last = b->last + buf_len + 2;
                b->last = b->last + buf_len + 2;
                cl->buf->temporary = (buf_len ? 1 : 0);
                //ctx->from_downstream = cl;
            } else {
                *cl->buf = *c->buffer;
            }
        }

        cl->buf->tag = (ngx_buf_tag_t) &ngx_stream_dns_proxy_module;
        cl->buf->flush = 1;

        cl->next = u->upstream_out;
        u->upstream_out = cl;
    }
done:
    u->connected = 1;

    pc->read->handler = ngx_stream_dns_proxy_upstream_handler;
    pc->write->handler = ngx_stream_dns_proxy_upstream_handler;

    if (pc->read->ready) {
        ngx_post_event(pc->read, &ngx_posted_events);
    }

    ngx_stream_dns_proxy_process(s, 0, do_write);
}

static void
ngx_stream_dns_proxy_downstream_handler(ngx_event_t *ev)
{
    ngx_stream_dns_proxy_process_connection(ev, ev->write);
}

static void
ngx_stream_dns_proxy_upstream_handler(ngx_event_t *ev)
{
    ngx_stream_dns_proxy_process_connection(ev, !ev->write);
}

static void
ngx_stream_dns_proxy_process_connection(ngx_event_t *ev, ngx_uint_t from_upstream)
{
    ngx_connection_t             *c, *pc;
    ngx_stream_session_t         *s;
    ngx_stream_upstream_t        *u;

    c = ev->data;
    s = c->data;
    u = s->upstream;

    if (c->close) {
        ngx_log_error(NGX_LOG_INFO, c->log, 0, "shutdown timeout");
        ngx_stream_dns_proxy_finalize(s, NGX_STREAM_OK);
        return;
    }

    c = s->connection;
    pc = u->peer.connection;

    if (ev->timedout) {
        ev->timedout = 0;

        if (s->connection->type == SOCK_DGRAM) {

            ngx_connection_error(pc, NGX_ETIMEDOUT, "upstream timed out");

            pc->read->error = 1;

            ngx_stream_dns_proxy_finalize(s, NGX_STREAM_BAD_GATEWAY);

            return;
        }

        ngx_connection_error(c, NGX_ETIMEDOUT, "connection timed out");

        ngx_stream_dns_proxy_finalize(s, NGX_STREAM_OK);

        return;
    }

    if (from_upstream && !u->connected) {
        return;
    }

    ngx_stream_dns_proxy_process(s, from_upstream, ev->write);
}


static void
ngx_stream_dns_proxy_connect_handler(ngx_event_t *ev)
{
    ngx_connection_t      *c;
    ngx_stream_session_t  *s;

    c = ev->data;
    s = c->data;

    if (ev->timedout) {
        ngx_log_error(NGX_LOG_ERR, c->log, NGX_ETIMEDOUT, "upstream timed out");
        ngx_stream_dns_proxy_next_upstream(s);
        return;
    }

    ngx_del_timer(c->write);

    ngx_log_debug0(NGX_LOG_DEBUG_STREAM, c->log, 0,
                   "stream proxy connect upstream");

    if (ngx_stream_dns_proxy_test_connect(c) != NGX_OK) {
        ngx_stream_dns_proxy_next_upstream(s);
        return;
    }

    ngx_stream_dns_proxy_init_upstream(s);
}

static ngx_int_t
ngx_stream_dns_proxy_test_connect(ngx_connection_t *c)
{
    int        err;
    socklen_t  len;

#if (NGX_HAVE_KQUEUE)

    if (ngx_event_flags & NGX_USE_KQUEUE_EVENT)  {
        err = c->write->kq_errno ? c->write->kq_errno : c->read->kq_errno;

        if (err) {
            (void) ngx_connection_error(c, err,
                                    "kevent() reported that connect() failed");
            return NGX_ERROR;
        }

    } else
#endif
    {
        err = 0;
        len = sizeof(int);

        /*
         * BSDs and Linux return 0 and set a pending error in err
         * Solaris returns -1 and sets errno
         */

        if (getsockopt(c->fd, SOL_SOCKET, SO_ERROR, (void *) &err, &len)
            == -1)
        {
            err = ngx_socket_errno;
        }

        if (err) {
            (void) ngx_connection_error(c, err, "connect() failed");
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}

static void
ngx_stream_dns_proxy_process(ngx_stream_session_t *s, ngx_uint_t from_upstream,
    ngx_uint_t do_write)
{
    char                         *recv_action, *send_action;
    off_t                        *received;
    size_t                        size;
    ssize_t                       n;
    ngx_buf_t                    *b;
    ngx_int_t                     rc;
    ngx_uint_t                    flags, *packets, proxy_flag;
    ngx_chain_t                  *cl = NULL, **ll = NULL, **out, **busy, *fl = NULL;
    ngx_connection_t             *c, *pc, *src, *dst;
    ngx_log_handler_pt            handler;
    ngx_stream_upstream_t        *u;
    ngx_stream_dns_proxy_srv_conf_t  *pscf;
    ngx_stream_dns_proxy_ctx_t   *ctx;
    uint16_t tcp_rcv_len = 0, pos = 0, temp_len = 0;

    u = s->upstream;

    c = s->connection;

    pc = u->connected ? u->peer.connection : NULL;
    /*ngx_log_debug3(NGX_LOG_DEBUG_STREAM, c->log, 0,
                   "ngx_stream_dns_proxy_process() form_upstream: %d, c sock type: %s, p socke type: %s", 
                   from_upstream, 
                   c->type == SOCK_STREAM ?"SOCK_STREAM":"SOCK_DGRAM",
                   pc->type == SOCK_STREAM ?"SOCK_STREAM":"SOCK_DGRAM");*/

    if (c->type == SOCK_DGRAM && (ngx_terminate || ngx_exiting)) {

        /* socket is already closed on worker shutdown */

        handler = c->log->handler;
        c->log->handler = NULL;

        ngx_log_error(NGX_LOG_INFO, c->log, 0, "disconnected on shutdown");

        c->log->handler = handler;

        ngx_stream_dns_proxy_finalize(s, NGX_STREAM_OK);
        return;
    }

    pscf = ngx_stream_get_module_srv_conf(s, ngx_stream_dns_proxy_module);

    if (from_upstream) {
        src = pc;
        dst = c;

        b = &u->upstream_buf;

        received = &u->received;
        packets = &u->responses;
        out = &u->downstream_out;
        busy = &u->downstream_busy;
        recv_action = "proxying and reading from upstream";
        send_action = "proxying and sending to client";

    } else {
        src = c;
        dst = pc;

        b = &u->downstream_buf;

        received = &s->received;
        packets = &u->requests;
        out = &u->upstream_out;
        busy = &u->upstream_busy;
        recv_action = "proxying and reading from client";
        send_action = "proxying and sending to upstream";
    }

    if (pscf->type != NGX_CONF_UNSET &&
            c->type != pscf->type) {
        proxy_flag = 1;
    } else {
        proxy_flag = 0;
    }
    ctx = ngx_stream_get_module_ctx(s, ngx_stream_dns_proxy_module);

    for ( ;; ) {

        if (do_write && dst) {

            if (*out || *busy || dst->buffered) {
                c->log->action = send_action;

                ngx_log_debug1(NGX_LOG_DEBUG_STREAM, c->log, 0,
                   "stream top filter: l: %d", (*out)->buf->last - (*out)->buf->pos);

                rc = ngx_stream_top_filter(s, *out, from_upstream);

                if (rc == NGX_ERROR) {
                    ngx_stream_dns_proxy_finalize(s, NGX_STREAM_OK);
                    return;
                }

                ngx_chain_update_chains(c->pool, &u->free, busy, out,
                                      (ngx_buf_tag_t) &ngx_stream_dns_proxy_module);

                if (*busy == NULL) {
                    b->pos = b->start;
                    b->last = b->start;
                }

            }
        }

        size = b->end - b->last;

        if (size && src->read->ready && !src->read->delayed
            && !src->read->error)
        {

            c->log->action = recv_action;

            if (src->type == SOCK_STREAM) {
                if (from_upstream) {
                    fl = ctx->from_upstream;
                    ctx->from_upstream = NULL;
                } else {
                    fl = ctx->from_downstream;
                    ctx->from_downstream = NULL;
                }

                if (fl == NULL) {
                    pos = 0;
                    fl = ngx_chain_get_free_buf(c->pool, &u->free);
                    if (fl == NULL) {
                        ngx_stream_dns_proxy_finalize(s,
                                NGX_STREAM_INTERNAL_SERVER_ERROR);
                        return;
                    }
                    fl->buf->pos = fl->buf->start;
                    fl->buf->last = fl->buf->start;
                } else {
                    pos = fl->buf->last - fl->buf->pos;
                }

                if (pos < 2) {
                    n = src->recv(src, b->last, 2 - pos);
                    if (n <= 0) {
                        goto Error;
                    }
                    if (fl->buf->pos == fl->buf->start) {
                        fl->buf->pos = b->last;
                    }
                    if ((pos + n) != 2) {
                        fl->buf->last = b->last + n;
                        b->last += n;
                        if (from_upstream) {
                            ctx->from_upstream = fl;
                        } else {
                            ctx->from_downstream = fl;
                        }
                        break;
                    }
                    b->last += n;
                    pos = 2;
                }
                tcp_rcv_len = ntohs(*((uint16_t*)fl->buf->pos));

                if (tcp_rcv_len < pos - 2) {
                    ngx_stream_dns_proxy_finalize(s,
                            NGX_STREAM_INTERNAL_SERVER_ERROR);
                    return;
                }
                pos = tcp_rcv_len - (pos - 2);
                size = pos > size ? size : pos;

                n = src->recv(src, b->last, size);
                if (n <= 0) {
                    goto Error;
                }
                if (n != pos) {
                    fl->buf->last = b->last + n;
                    b->last += n;
                    if (from_upstream) {
                        ctx->from_upstream = fl;
                    } else {
                        ctx->from_downstream = fl;
                    }
                    break;
                }
                b->last += n;
                fl->buf->last = b->last;
                n = tcp_rcv_len + 2;
                if (proxy_flag) {
                    //n = n - 2;
                    fl->buf->pos = fl->buf->pos + 2;
                }
            } else {
                if (proxy_flag) {
                    n = src->recv(src, b->last + 2, size - 2);
                    if (n > 0) {
                        temp_len = htons((uint16_t)n);
                        ngx_memcpy(b->last, (char *)&temp_len, 2);
                    }
                    n += 2;
                } else {
                    n = src->recv(src, b->last, size);
                }
            }
Error:
            if (n == NGX_AGAIN) {
                break;
            }

            if (n == NGX_ERROR) {
                src->read->eof = 1;
                n = 0;
            }

            if (n >= 0) {
                /*
                if (from_upstream) {
                    if (u->state->first_byte_time == (ngx_msec_t) -1) {
                        u->state->first_byte_time = ngx_current_msec
                                                    - u->start_time;
                    }
                }*/

                for (ll = out; *ll; ll = &(*ll)->next) { /* void */ }

                if (fl == NULL) {
                    cl = ngx_chain_get_free_buf(c->pool, &u->free);
                    if (cl == NULL) {
                        ngx_stream_dns_proxy_finalize(s,
                                NGX_STREAM_INTERNAL_SERVER_ERROR);
                        return;
                    }
                } else {
                    cl = fl;
                }
                *ll = cl;

                if (fl == NULL) {
                    cl->buf->pos = b->last;
                    cl->buf->last = b->last + n;
                }
                cl->buf->tag = (ngx_buf_tag_t) &ngx_stream_dns_proxy_module;

                cl->buf->temporary = (n ? 1 : 0);
                cl->buf->last_buf = src->read->eof;
                cl->buf->flush = 1;

                (*packets)++;

                *received += n;

                if (fl == NULL) {
                    b->last += n;
                } else {
                    fl = NULL;
                }

                do_write = 1;

                continue;
            }
        }

        break;
    }

    c->log->action = "proxying connection";

    if (ngx_stream_dns_proxy_test_finalize(s, from_upstream) == NGX_OK) {
        return;
    }

    flags = src->read->eof ? NGX_CLOSE_EVENT : 0;

    if (!src->shared && ngx_handle_read_event(src->read, flags) != NGX_OK) {
        ngx_stream_dns_proxy_finalize(s, NGX_STREAM_INTERNAL_SERVER_ERROR);
        return;
    }

    if (dst) {
        if (!dst->shared && ngx_handle_write_event(dst->write, 0) != NGX_OK) {
            ngx_stream_dns_proxy_finalize(s, NGX_STREAM_INTERNAL_SERVER_ERROR);
            return;
        }

        if (!c->read->delayed && !pc->read->delayed) {
            ngx_add_timer(c->write, pscf->timeout);
        } else if (c->write->timer_set) {
            ngx_del_timer(c->write);
        }
    }
}


static ngx_int_t
ngx_stream_dns_proxy_test_finalize(ngx_stream_session_t *s,
    ngx_uint_t from_upstream)
{
    ngx_connection_t             *c, *pc;
    ngx_log_handler_pt            handler;
    ngx_stream_upstream_t        *u;

    c = s->connection;
    u = s->upstream;
    pc = u->connected ? u->peer.connection : NULL;

    if (c->type == SOCK_DGRAM) {
        /*
        if (pscf->requests && u->requests < pscf->requests) {
            return NGX_DECLINED;
        }*/

        /*if (pscf->requests) {
            ngx_delete_udp_connection(c);
        }*/

        /*if (pscf->responses == NGX_MAX_INT32_VALUE
            || u->responses < pscf->responses * u->requests)
        {
            return NGX_DECLINED;
        }*/
        if (u->responses < u->requests)
        {
            return NGX_DECLINED;
        }

        if (pc == NULL || c->buffered || pc->buffered) {
            return NGX_DECLINED;
        }

        handler = c->log->handler;
        c->log->handler = NULL;

        ngx_log_error(NGX_LOG_INFO, c->log, 0,
                      "udp done"
                      ", packets from/to client:%ui/%ui"
                      ", bytes from/to client:%O/%O"
                      ", bytes from/to upstream:%O/%O",
                      u->requests, u->responses,
                      s->received, c->sent, u->received, pc ? pc->sent : 0);

        c->log->handler = handler;

        ngx_stream_dns_proxy_finalize(s, NGX_STREAM_OK);

        return NGX_OK;
    }

    /* c->type == SOCK_STREAM */

    if (pc == NULL
        || (!c->read->eof && !pc->read->eof)
        || (!c->read->eof && c->buffered)
        || (!pc->read->eof && pc->buffered))
    {
        return NGX_DECLINED;
    }

    handler = c->log->handler;
    c->log->handler = NULL;

    ngx_log_error(NGX_LOG_INFO, c->log, 0,
                  "%s disconnected"
                  ", bytes from/to client:%O/%O"
                  ", bytes from/to upstream:%O/%O",
                  from_upstream ? "upstream" : "client",
                  s->received, c->sent, u->received, pc ? pc->sent : 0);

    c->log->handler = handler;

    ngx_stream_dns_proxy_finalize(s, NGX_STREAM_OK);

    return NGX_OK;
}


static void
ngx_stream_dns_proxy_next_upstream(ngx_stream_session_t *s)
{
    ngx_msec_t                    timeout;
    ngx_connection_t             *pc;
    ngx_stream_upstream_t        *u;
    ngx_stream_dns_proxy_srv_conf_t  *pscf;

    ngx_log_debug0(NGX_LOG_DEBUG_STREAM, s->connection->log, 0,
                   "stream proxy next upstream");

    u = s->upstream;
    pc = u->peer.connection;

    if (pc && pc->buffered) {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                      "buffered data on next upstream");
        ngx_stream_dns_proxy_finalize(s, NGX_STREAM_INTERNAL_SERVER_ERROR);
        return;
    }

    if (s->connection->type == SOCK_DGRAM) {
        u->upstream_out = NULL;
    }

    if (u->peer.sockaddr) {
        u->peer.free(&u->peer, u->peer.data, NGX_PEER_FAILED);
        u->peer.sockaddr = NULL;
    }

    pscf = ngx_stream_get_module_srv_conf(s, ngx_stream_dns_proxy_module);

    timeout = pscf->next_upstream_timeout;

    if (u->peer.tries == 0
        || !pscf->next_upstream
        || (timeout && ngx_current_msec - u->peer.start_time >= timeout))
    {
        ngx_stream_dns_proxy_finalize(s, NGX_STREAM_BAD_GATEWAY);
        return;
    }

    if (pc) {
        ngx_log_debug1(NGX_LOG_DEBUG_STREAM, s->connection->log, 0,
                       "close proxy upstream connection: %d", pc->fd);

        u->state->bytes_received = u->received;
        u->state->bytes_sent = pc->sent;

        ngx_close_connection(pc);
        u->peer.connection = NULL;
    }

    ngx_stream_dns_proxy_connect(s);
}


static void
ngx_stream_dns_proxy_finalize(ngx_stream_session_t *s, ngx_uint_t rc)
{
    ngx_uint_t              state;
    ngx_connection_t       *pc;
    ngx_stream_upstream_t  *u;
    ngx_stream_dns_proxy_ctx_t   *ctx;

    ngx_log_debug1(NGX_LOG_DEBUG_STREAM, s->connection->log, 0,
                   "finalize stream dns proxy: %i", rc);

    ctx = ngx_stream_get_module_ctx(s, ngx_stream_dns_proxy_module);

    u = s->upstream;

    if (u == NULL) {
        goto noupstream;
    }

    if (ctx != NULL) {
        if (ctx->from_upstream != NULL) {
            ctx->from_upstream->buf->pos = ctx->from_upstream->buf->start;
            ctx->from_upstream->buf->last = ctx->from_upstream->buf->start;
            ngx_free_chain(s->connection->pool, ctx->from_upstream);
        }
        if (ctx->from_downstream != NULL) {
            ctx->from_downstream->buf->pos = ctx->from_downstream->buf->start;
            ctx->from_downstream->buf->last = ctx->from_downstream->buf->start;
            ngx_free_chain(s->connection->pool, ctx->from_downstream);
        }
    }

    if (u->resolved && u->resolved->ctx) {
        ngx_resolve_name_done(u->resolved->ctx);
        u->resolved->ctx = NULL;
    }

    pc = u->peer.connection;

    if (u->state) {
        /*
        if (u->state->response_time == (ngx_msec_t) -1) {
            u->state->response_time = ngx_current_msec - u->start_time;
        }*/

        if (pc) {
            u->state->bytes_received = u->received;
            u->state->bytes_sent = pc->sent;
        }
    }

    if (u->peer.free && u->peer.sockaddr) {
        state = 0;

        if (pc && pc->type == SOCK_DGRAM
            && (pc->read->error || pc->write->error))
        {
            state = NGX_PEER_FAILED;
        }

        u->peer.free(&u->peer, u->peer.data, state);
        u->peer.sockaddr = NULL;
    }

    if (pc) {
        ngx_log_debug1(NGX_LOG_DEBUG_STREAM, s->connection->log, 0,
                       "close stream proxy upstream connection: %d", pc->fd);

        ngx_close_connection(pc);
        u->peer.connection = NULL;
    }

noupstream:

    ngx_stream_finalize_session(s, rc);
}


static u_char *
ngx_stream_dns_proxy_log_error(ngx_log_t *log, u_char *buf, size_t len)
{
    u_char                 *p;
    ngx_connection_t       *pc;
    ngx_stream_session_t   *s;
    ngx_stream_upstream_t  *u;

    s = log->data;

    u = s->upstream;

    p = buf;

    if (u->peer.name) {
        p = ngx_snprintf(p, len, ", upstream: \"%V\"", u->peer.name);
        len -= p - buf;
    }

    pc = u->peer.connection;

    p = ngx_snprintf(p, len,
                     ", bytes from/to client:%O/%O"
                     ", bytes from/to upstream:%O/%O",
                     s->received, s->connection->sent,
                     u->received, pc ? pc->sent : 0);

    return p;
}


static void *
ngx_stream_dns_proxy_create_srv_conf(ngx_conf_t *cf)
{
    ngx_stream_dns_proxy_srv_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_stream_dns_proxy_srv_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->connect_timeout = NGX_CONF_UNSET_MSEC;
    conf->timeout = NGX_CONF_UNSET_MSEC;
    conf->next_upstream_timeout = NGX_CONF_UNSET_MSEC;
    conf->buffer_size = NGX_CONF_UNSET_SIZE;
    conf->next_upstream_tries = NGX_CONF_UNSET_UINT;
    conf->next_upstream = NGX_CONF_UNSET;
    conf->type = NGX_CONF_UNSET;

    return conf;
}


static char *
ngx_stream_dns_proxy_merge_srv_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_stream_dns_proxy_srv_conf_t *prev = parent;
    ngx_stream_dns_proxy_srv_conf_t *conf = child;

    ngx_conf_merge_msec_value(conf->connect_timeout,
                              prev->connect_timeout, 6000);

    ngx_conf_merge_msec_value(conf->timeout,
                              prev->timeout, 6000);

    ngx_conf_merge_msec_value(conf->next_upstream_timeout,
                              prev->next_upstream_timeout, 6000);

    ngx_conf_merge_size_value(conf->buffer_size,
                              prev->buffer_size, 4096);

    ngx_conf_merge_uint_value(conf->next_upstream_tries,
                              prev->next_upstream_tries, 0);

    return NGX_CONF_OK;
}

static char *
ngx_stream_dns_proxy_pass(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_stream_dns_proxy_srv_conf_t *pscf = conf;

    ngx_url_t                            u;
    ngx_str_t                           *value, *url, *protocol;
    ngx_stream_core_srv_conf_t          *cscf;

    if (pscf->upstream) {
        return "is duplicate";
    }

    cscf = ngx_stream_conf_get_module_srv_conf(cf, ngx_stream_core_module);

    cscf->handler = ngx_stream_dns_proxy_handler;

    value = cf->args->elts;

    url = &value[1];

    ngx_memzero(&u, sizeof(ngx_url_t));

    u.url = *url;
    u.no_resolve = 1;

    pscf->upstream = ngx_stream_upstream_add(cf, &u, 0);
    if (pscf->upstream == NULL) {
        return NGX_CONF_ERROR;
    }

    if (cf->args->nelts > 2) {
        protocol = &value[2];
        if (!ngx_strncasecmp(protocol->data, (void *)"tcp", 3)) {
            pscf->type = SOCK_STREAM;
        } else if (!ngx_strncasecmp(protocol->data, (void *)"udp", 3)) {
            pscf->type = SOCK_DGRAM;
        } else {
            return NGX_CONF_ERROR;
        }
    }

    return NGX_CONF_OK;
}

static ngx_int_t
ngx_stream_dns_write_filter(ngx_stream_session_t *s, ngx_chain_t *in,
    ngx_uint_t from_upstream)
{
    ngx_int_t ret = 0;

    //ngx_log_debug0(NGX_LOG_DEBUG_STREAM, s->connection->log, 0, "ngx_stream_dns_write_filter() start ...");
    ngx_stream_parse_dns_package(s, in, from_upstream);
    //ngx_log_debug0(NGX_LOG_DEBUG_STREAM, s->connection->log, 0, "ngx_stream_dns_write_filter() stop ...");

    ret = ngx_stream_next_filter(s, in, from_upstream);

    return ret;
}

static ngx_int_t
ngx_stream_dns_write_filter_init(ngx_conf_t *cf)
{
    ngx_stream_next_filter = ngx_stream_top_filter;
    ngx_stream_top_filter = ngx_stream_dns_write_filter;

    return NGX_OK;
}

static ngx_int_t
ngx_stream_variable_dns_answer_context(ngx_stream_session_t *s,
     ngx_stream_variable_value_t *v, uintptr_t data)
{
    ngx_stream_dns_proxy_ctx_t  *ctx;
    ngx_dns_rr_t *answer;
    ngx_list_part_t *part;
    u_char text[NGX_INET6_ADDRSTRLEN + 1] = {};
    u_char ntext[NGX_INET6_ADDRSTRLEN + 1] = {};
    ngx_str_t context;
    size_t context_len = 0;
    ngx_uint_t i = 0;
    size_t ip_len = 0;
    u_char *p = NULL;

    ctx = ngx_stream_get_module_ctx(s, ngx_stream_dns_proxy_module);

    if (ctx == NULL || ctx->answer_msg.answer == NULL 
            || ctx->answer_msg.answer->part.nelts == 0) {
        goto notfind;
    }

    part = &(ctx->answer_msg.answer->part);
    answer = (ngx_dns_rr_t *)part->elts;
    // Calculate length
    for(i = 0; ; i ++) {
        if(i >= part->nelts) {
            if(part->next != NULL) {
                part = part->next;
                answer = (ngx_dns_rr_t *)part->elts;
            } else {
                break;
            }
            i = 0;
        }
        // domain len
        context_len += answer[i].name.len;
        // data
        if(answer[i].rtype == TypeA) {
            context_len += NGX_INET_ADDRSTRLEN;
        } else if(answer[i].rtype == TypeAAAA){
            context_len += NGX_INET6_ADDRSTRLEN;
        } else {
            context_len += answer[i].rdlength;
        }
        // rtype rclass rttl
        context_len += 20;
    }

    //context_len += 12;
    context.data = ngx_palloc(s->connection->pool, context_len);

    part = &(ctx->answer_msg.answer->part);
    answer = (ngx_dns_rr_t *)part->elts;
    p = context.data;
    //p = ngx_snprintf(context.data, context_len, "DNS ANSWER: ");
    // pos += p - context.data;
    for(i = 0; ; i ++) {
        ip_len = 0;
        if(i >= part->nelts) {
            if(part->next != NULL) {
                part = part->next;
                answer = (ngx_dns_rr_t *)part->elts;
            } else {
                break;
            }
            i = 0;
        }
        if(answer[i].rtype == TypeA) {
            ngx_memcpy(ntext, answer[i].rdata.data, answer[i].rdata.len + 1);
            ntext[answer[i].rdata.len] = '\0';
            ip_len = ngx_inet_ntop(AF_INET, ntext, text, NGX_INET_ADDRSTRLEN);
        } else if(answer[i].rtype == TypeAAAA) {
            ngx_memcpy(ntext, answer[i].rdata.data, answer[i].rdata.len);
            ntext[answer->rdata.len] = '\0';
            ip_len = ngx_inet_ntop(AF_INET6, ntext, text, NGX_INET6_ADDRSTRLEN);
        }

        if(ip_len != 0) {
            p = ngx_cpymem(p, answer[i].name.data, answer[i].name.len);
            p = ngx_snprintf(p, context_len, " %d %s %s ",
                    answer[i].rttl,
                    ngx_dns_class_type_string(answer[i].rclass),
                    ngx_dns_type_string(answer[i].rtype));
            p = ngx_cpymem(p, text, ip_len);
        } else {
            p = ngx_cpymem(p, answer[i].name.data, answer[i].name.len);
            p = ngx_snprintf(p, context_len, " %d %s %s ",
                    answer[i].rttl,
                    ngx_dns_class_type_string(answer[i].rclass),
                    ngx_dns_type_string(answer[i].rtype));
            p = ngx_cpymem(p, answer[i].rdata.data, answer[i].rdata.len);
        }
        p = ngx_snprintf(p, context_len, "; ");
    }

    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->len = p - context.data;
    v->data = context.data;

    return NGX_OK;
notfind:
    v->not_found = 1;
    return NGX_OK;
}

static ngx_int_t
ngx_stream_variable_dns_question_context(ngx_stream_session_t *s,
     ngx_stream_variable_value_t *v, uintptr_t data)
{
    ngx_stream_dns_proxy_ctx_t  *ctx;
    u_char *p = NULL;
    ngx_dns_question_t *question;
    ngx_str_t context;
    ngx_int_t context_len;
    ngx_list_part_t *part;

    ctx = ngx_stream_get_module_ctx(s, ngx_stream_dns_proxy_module);

    if (ctx == NULL || ctx->question_msg.question == NULL) {
        goto notfind;
    }

    part = &(ctx->question_msg.question->part);
    if(part->nelts == 0) {
        goto notfind;
    }

    question = (ngx_dns_question_t *)part->elts;
    if(question == NULL) {
        goto notfind;
    }

    context_len = question->name.len + 30;
    context.data = ngx_palloc(s->connection->pool, question->name.len + 30);
    if(context.data == NULL) {
        goto notfind;
    }

    question = (ngx_dns_question_t *)part->elts;
    //p = ngx_snprintf(context.data, context_len, "DNS QUESTION: "); 
    p = context.data;
    p = ngx_cpymem(p, question->name.data, question->name.len);
    p = ngx_snprintf(p, context_len, " %s %s",
            ngx_dns_class_type_string(question->qclass),
            ngx_dns_type_string(question->qtype));

    context.len = p - context.data;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->len = context.len;
    v->data = context.data;

    return NGX_OK;
notfind:

    v->not_found = 1;
    return NGX_OK;
}

static ngx_int_t
ngx_stream_dns_add_vars(ngx_conf_t* cf)
{
    ngx_stream_variable_t        *nv, *v;
    
    for (nv = ngx_stream_dns_variables; nv->name.len; nv++)
    {
        v = ngx_stream_add_variable(cf, &nv->name, nv->flags);
        if (!v)
        {
            ngx_log_error(NGX_LOG_ERR, cf->log, 0,"add var:%V error!", &nv->name);

            return NGX_ERROR;
        }
        v->get_handler = nv->get_handler;
        v->data = nv->data;
    }

    return NGX_OK;
}
