# Nginx ngx_ssl_session_cache_module

[![License](https://img.shields.io/badge/LICENSE-Apache2.0-ff69b4.svg)](http://www.apache.org/licenses/LICENSE-2.0.html)  

# Description

This module provide a distributed session reuse function, support redis, memcached, support long connection and full asynchronous mode

This module was developed based on openssl-1.0.2j early, Involved a large number of source code changes with openssl, due to the high cost of ops, then migrate to openssl-1.1.0e, using the high version of the asynchronous mode to complete the openssl code decoupling

However, there is also need to make some changes to the nginx code, see patch

# Prerequisite

- Openssl >= 1.1.0
- Nginx >= 1.9.14
- Redis >= 2.0
- Memcached >= 1.4.3

# Directives

## remote_ssl_session_cache
  
**Syntax:** *remote_ssl_session_cache [on | off] addr=address*  
　　　　*[port=number] [type=redis | memcached] [interval=number]*  
　　　　*[count=size] [timeout=number] [auth=password]*

**Default:** *remote_ssl_session_cache on*  
　　　　*addr=127.0.0.1 port=6379 type=redis interval=200 count=5000 timeout=1000*

**Context:** *http,server*

*   on/off

    * Enable or Disable the distributed session reuse function.

*   addr
    
    * Set the address of the cache system, support domain

*   port

    * Set the port of the cache system

*   type
    
    * Set the type of the cache system, redis or memcached 

*   interval

    * Set the interval of keepalive check or reconnect

*   count

    * Set the queue size, enqueue when set or get, dequeue when cache system return, support unlimited

*   timeout

    * Set the read/write/connect timeout

*   auth

    * set the password for authentication

# Compilation

	1. pathch –p0 < path-to-module/nginx_1.12.0_ssl_session_cache.patch
	2. path-to-nginx/configure --add-module=path-to-module/cache_type/memcached --add-module=path-to-module/cache_type/redis

# Author

*   wywujianmiao@jd.com
*   jrliqing@jd.com
*   gengxiaotian@jd.com
*   jrwangshimeng@jd.com