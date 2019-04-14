# ngx_stream_dns_proxy_module
## Description
DNS forward server based on nginx stream module implementation.

## Installation

```
$ cd nginx-1.x.x
$ ./configure --prefix=/root/nginx_sty/nginx_bin --add-module=/path/ngx_stream_dns_proxy_module --with-stream
$ make && make install

```

## Configuration directives

### `dns_proxy_pass`

- **syntax**: `dns_proxy_pass address tcp|udp`
- **default**: `-`
- **context**: `server`

Sets the address of a proxied server. The address can be specified as IP address, and a port.

### `dns_proxy_connect_timeout`

- **syntax**: `dns_proxy_connect_timeout timeout`
- **default**: `6s`
- **context**: `stream`,`server`

Defines a timeout for establishing a connection with a proxied server.

### `dns_proxy_timeout`

- **syntax**: `dns_proxy_timeout timeout`
- **default**: `6s`
- **context**: `stream`,`server`

Sets the timeout between two successive read or write operations on client or proxied server connections. If no data is transmitted within this time, the connection is closed.

### `dns_decode_packet_enable`

- **syntax**: `dns_decode_packet_enable on|off`
- **default**: `on`
- **context**: `stream`,`server`

'dns_decode_pacet_enable' is set to off, all variables are invalidated

## Variables

### `$dns_answer_content`

Formatting DNS answer content.(support only A and AAAA)

### `$dns_question_content`

Formatting DNS query content.

## Usage

```
stream {
	log_format dnsfmt 'DNS Question: $dns_question_content DNS Answer: $dns_answer_content';
	server {
		listen 53 udp;
		# dns_proxy_pass 114.114.114.114:53 tcp;
		dns_proxy_pass 114.114.114.114:53;
		access_log /root/nginx_sty/nginx_bin/logs/dns-access.log dnsfmt;
	}

	server {
		listen 53;
		# dns_proxy_pass 8.8.8.8:53 udp;
		dns_proxy_pass 8.8.8.8:53;
		access_log /root/nginx_sty/nginx_bin/logs/dns-access.log dnsfmt;
	}
}

output:
# dig @127.0.0.1 www.baidu.com

; <<>> DiG 9.11.2 <<>> @127.0.0.1 www.baidu.com
; (1 server found)
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 8135
;; flags: qr rd ra; QUERY: 1, ANSWER: 3, AUTHORITY: 0, ADDITIONAL: 1

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 4096
;; QUESTION SECTION:
;www.baidu.com.			IN	A

;; ANSWER SECTION:
www.baidu.com.		782	IN	CNAME	www.a.shifen.com.
www.a.shifen.com.	103	IN	A	61.135.169.125
www.a.shifen.com.	103	IN	A	61.135.169.121

;; Query time: 16 msec
;; SERVER: 127.0.0.1#53(127.0.0.1)
;; WHEN: Sat Apr 13 23:08:01 CST 2019
;; MSG SIZE  rcvd: 101

access_lout output:
# cat dns-access.log
DNS Question: www.baidu.com IN A DNS Answer: www.baidu.com 782 IN CNAME www.a.shifen.com; www.a.shifen.com 103 IN A 61.135.169.125; www.a.shifen.com 103 IN A 61.135.169.121;
```
