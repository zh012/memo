# haproxy + rsyslog

#### No

As haproxy writes log to syslog, which is using UDS DGRAM to transfer data.

Not matter how the system configurations are tunned, the data lost is continuously observed.

```
net.core.somaxconn = 65535
net.unix.max_dgram_qlen = 65535
net.core.rmem_default = 65536
net.core.rmem_max = 8388608
net.core.wmem_default = 65536
net.core.wmem_max = 8388608
net.core.netdev_max_backlog = 20000
net.core.message_burst = 10
net.core.message_cost = 0
```

IP UDP could also be used, but the situation is just worse, since it'd much slower than UDS and drop packets more often.


# haproxy + nodejs http server

To be evaluated


# nginx

Use access_log of nginx is pretty reliable.

```
user www-data;
worker_processes  4;
worker_rlimit_nofile 50000;
error_log logs/error.log;
events {
    worker_connections 40000;
}

http {
    server {
        server_name SERVER_IP_ADDRESS;
        listen 80;
        location / {
            return 200;
            default_type text/plain;
            client_max_body_size 1k;
            client_body_buffer_size 1k;
            access_log /data/tracker/http.log;
        }
    }
}
```