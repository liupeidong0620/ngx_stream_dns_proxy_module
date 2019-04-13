# ngx_stream_dns_proxy_module
## Description
DNS forward server based on nginx stream module implementation.

## Installation

```
#
# download the newest source
# @see http://nginx.org/en/download.html
#

git clone https://github.com/liupeidong0620/ngx_stream_dns_proxy_module.git

./configure --prefix=/root/nginx_sty/nginx_bin --add-module=/path/ngx_stream_dns_proxy_module --with-stream
```
## Usage

```
stream {
	log_format dnsfmt 'DNS Question: $dns_question_context DNS Answer: $dns_answer_context';
	server {
		listen 53 udp;
		# dns_proxy_pass dns tcp;
		dns_proxy_pass dns;
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
