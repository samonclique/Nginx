# Nginx
A comprehensive guide to learning nginx
# Comprehensive Nginx Learning Guide

## Table of Contents
1. [Introduction](#introduction)
2. [Installation](#installation)
3. [Basic Concepts](#basic-concepts)
4. [Configuration Fundamentals](#configuration-fundamentals)
5. [Serving Static Content](#serving-static-content)
6. [Reverse Proxy](#reverse-proxy)
7. [Load Balancing](#load-balancing)
8. [SSL/TLS Configuration](#ssltls-configuration)
9. [Security Best Practices](#security-best-practices)
10. [Performance Optimization](#performance-optimization)
11. [Logging and Monitoring](#logging-and-monitoring)
12. [Advanced Features](#advanced-features)
13. [Common Use Cases](#common-use-cases)
14. [Troubleshooting](#troubleshooting)
15. [Learning Resources](#learning-resources)

## Introduction

Nginx (pronounced "engine-x") is a high-performance web server, reverse proxy server, and load balancer. Originally created by Igor Sysoev in 2004, it's designed to handle high concurrent connections with low memory usage.

### Key Features
- High performance and low resource consumption
- Reverse proxy capabilities
- Load balancing
- SSL/TLS termination
- HTTP/2 support
- Caching
- Rate limiting
- WebSocket support

## Installation

### Ubuntu/Debian
```bash
sudo apt update
sudo apt install nginx
```

### CentOS/RHEL/Fedora
```bash
# CentOS/RHEL
sudo yum install nginx
# or for newer versions
sudo dnf install nginx

# Fedora
sudo dnf install nginx
```

### macOS
```bash
brew install nginx
```

### From Source
```bash
wget http://nginx.org/download/nginx-1.24.0.tar.gz
tar -xzf nginx-1.24.0.tar.gz
cd nginx-1.24.0
./configure --prefix=/etc/nginx --sbin-path=/usr/sbin/nginx
make
sudo make install
```

### Basic Commands
```bash
# Start nginx
sudo systemctl start nginx

# Stop nginx
sudo systemctl stop nginx

# Restart nginx
sudo systemctl restart nginx

# Reload configuration
sudo systemctl reload nginx

# Check status
sudo systemctl status nginx

# Test configuration
sudo nginx -t
```

## Basic Concepts

### Process Architecture
Nginx uses a master-worker process model:
- **Master Process**: Manages worker processes, reads configuration
- **Worker Processes**: Handle actual client requests
- **Cache Loader**: Loads disk cache into memory
- **Cache Manager**: Manages cache expiration

### Configuration Structure
Nginx configuration is organized in contexts (blocks):
- `main`: Global settings
- `events`: Connection processing
- `http`: HTTP-specific settings
- `server`: Virtual host settings
- `location`: URI-specific settings

### Directives
Configuration instructions that control Nginx behavior:
- **Simple directives**: End with semicolon
- **Block directives**: Contain other directives within braces

## Configuration Fundamentals

### Main Configuration File
Default location: `/etc/nginx/nginx.conf`

```nginx
# Global context
user nginx;
worker_processes auto;
error_log /var/log/nginx/error.log;
pid /run/nginx.pid;

# Events context
events {
    worker_connections 1024;
    use epoll;
}

# HTTP context
http {
    # Basic settings
    sendfile on;
    tcp_nopush on;
    tcp_nodelay on;
    keepalive_timeout 65;
    types_hash_max_size 2048;
    
    # MIME types
    include /etc/nginx/mime.types;
    default_type application/octet-stream;
    
    # Logging
    log_format main '$remote_addr - $remote_user [$time_local] "$request" '
                    '$status $body_bytes_sent "$http_referer" '
                    '"$http_user_agent" "$http_x_forwarded_for"';
    
    access_log /var/log/nginx/access.log main;
    
    # Virtual host configs
    include /etc/nginx/conf.d/*.conf;
    include /etc/nginx/sites-enabled/*;
}
```

### Virtual Hosts (Server Blocks)
```nginx
server {
    listen 80;
    server_name example.com www.example.com;
    root /var/www/example.com;
    index index.html index.php;
    
    access_log /var/log/nginx/example.com.access.log;
    error_log /var/log/nginx/example.com.error.log;
    
    location / {
        try_files $uri $uri/ =404;
    }
}
```

## Serving Static Content

### Basic Static File Serving
```nginx
server {
    listen 80;
    server_name static.example.com;
    root /var/www/static;
    
    location / {
        try_files $uri $uri/ =404;
    }
    
    # Cache static assets
    location ~* \.(jpg|jpeg|png|gif|ico|css|js)$ {
        expires 1y;
        add_header Cache-Control "public, immutable";
    }
    
    # Serve specific file types
    location ~* \.pdf$ {
        add_header Content-Disposition "attachment";
    }
}
```

### Directory Listings
```nginx
location /downloads/ {
    autoindex on;
    autoindex_exact_size off;
    autoindex_localtime on;
}
```

### Custom Error Pages
```nginx
error_page 404 /404.html;
error_page 500 502 503 504 /50x.html;

location = /404.html {
    root /var/www/error;
}

location = /50x.html {
    root /var/www/error;
}
```

## Reverse Proxy

### Basic Reverse Proxy
```nginx
server {
    listen 80;
    server_name app.example.com;
    
    location / {
        proxy_pass http://127.0.0.1:3000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

### Advanced Proxy Configuration
```nginx
upstream backend {
    server 127.0.0.1:3000;
}

server {
    listen 80;
    server_name app.example.com;
    
    location / {
        proxy_pass http://backend;
        
        # Headers
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        
        # Timeouts
        proxy_connect_timeout 30s;
        proxy_send_timeout 30s;
        proxy_read_timeout 30s;
        
        # Buffering
        proxy_buffering on;
        proxy_buffer_size 128k;
        proxy_buffers 4 256k;
        proxy_busy_buffers_size 256k;
    }
    
    # Static files served directly
    location /static/ {
        root /var/www/app;
        expires 30d;
    }
}
```

### WebSocket Proxying
```nginx
location /websocket/ {
    proxy_pass http://backend;
    proxy_http_version 1.1;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection "upgrade";
    proxy_set_header Host $host;
}
```

## Load Balancing

### Basic Load Balancing
```nginx
upstream backend {
    server 192.168.1.10:3000;
    server 192.168.1.11:3000;
    server 192.168.1.12:3000;
}

server {
    listen 80;
    server_name app.example.com;
    
    location / {
        proxy_pass http://backend;
    }
}
```

### Load Balancing Methods
```nginx
# Round Robin (default)
upstream backend {
    server srv1.example.com;
    server srv2.example.com;
}

# Least Connections
upstream backend {
    least_conn;
    server srv1.example.com;
    server srv2.example.com;
}

# IP Hash
upstream backend {
    ip_hash;
    server srv1.example.com;
    server srv2.example.com;
}

# Weighted Round Robin
upstream backend {
    server srv1.example.com weight=3;
    server srv2.example.com weight=1;
}
```

### Health Checks and Failover
```nginx
upstream backend {
    server srv1.example.com max_fails=3 fail_timeout=30s;
    server srv2.example.com max_fails=3 fail_timeout=30s;
    server srv3.example.com backup;  # Backup server
}
```

## SSL/TLS Configuration

### Basic SSL Setup
```nginx
server {
    listen 443 ssl http2;
    server_name example.com;
    
    ssl_certificate /path/to/certificate.crt;
    ssl_certificate_key /path/to/private.key;
    
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers off;
    
    location / {
        root /var/www/html;
    }
}

# Redirect HTTP to HTTPS
server {
    listen 80;
    server_name example.com;
    return 301 https://$server_name$request_uri;
}
```

### Advanced SSL Configuration
```nginx
# SSL session settings
ssl_session_cache shared:SSL:10m;
ssl_session_timeout 10m;
ssl_session_tickets off;

# OCSP stapling
ssl_stapling on;
ssl_stapling_verify on;
ssl_trusted_certificate /path/to/ca-bundle.crt;

# Security headers
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
add_header X-Frame-Options DENY always;
add_header X-Content-Type-Options nosniff always;
```

### Let's Encrypt with Certbot
```bash
# Install certbot
sudo apt install certbot python3-certbot-nginx

# Obtain certificate
sudo certbot --nginx -d example.com -d www.example.com

# Auto-renewal
sudo crontab -e
# Add: 0 12 * * * /usr/bin/certbot renew --quiet
```

## Security Best Practices

### Basic Security Headers
```nginx
# Security headers
add_header X-Frame-Options DENY always;
add_header X-Content-Type-Options nosniff always;
add_header X-XSS-Protection "1; mode=block" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
add_header Content-Security-Policy "default-src 'self'" always;

# Hide Nginx version
server_tokens off;
```

### Rate Limiting
```nginx
# Define rate limit zones
http {
    limit_req_zone $binary_remote_addr zone=login:10m rate=1r/s;
    limit_req_zone $binary_remote_addr zone=api:10m rate=10r/s;
}

server {
    # Apply rate limiting
    location /login {
        limit_req zone=login burst=5 nodelay;
        proxy_pass http://backend;
    }
    
    location /api/ {
        limit_req zone=api burst=20 nodelay;
        proxy_pass http://backend;
    }
}
```

### Access Control
```nginx
# IP-based access control
location /admin/ {
    allow 192.168.1.0/24;
    allow 10.0.0.0/8;
    deny all;
    
    proxy_pass http://backend;
}

# HTTP Basic Authentication
location /secure/ {
    auth_basic "Restricted Area";
    auth_basic_user_file /etc/nginx/.htpasswd;
    
    proxy_pass http://backend;
}
```

### Blocking Malicious Requests
```nginx
# Block common exploit attempts
location ~* \.(php|asp|aspx|jsp)$ {
    return 444;
}

# Block user agents
if ($http_user_agent ~* (bot|crawler|spider)) {
    return 403;
}

# Block based on request method
if ($request_method !~ ^(GET|HEAD|POST)$ ) {
    return 444;
}
```

## Performance Optimization

### Caching
```nginx
# Proxy caching
proxy_cache_path /var/cache/nginx levels=1:2 keys_zone=my_cache:10m 
                 max_size=10g inactive=60m use_temp_path=off;

server {
    location / {
        proxy_cache my_cache;
        proxy_cache_valid 200 302 10m;
        proxy_cache_valid 404 1m;
        proxy_cache_use_stale error timeout updating http_500 http_502 http_503 http_504;
        proxy_cache_lock on;
        
        proxy_pass http://backend;
    }
}
```

### Compression
```nginx
# Gzip compression
gzip on;
gzip_vary on;
gzip_min_length 1024;
gzip_comp_level 6;
gzip_types
    application/atom+xml
    application/javascript
    application/json
    application/rss+xml
    application/vnd.ms-fontobject
    application/x-font-ttf
    application/x-web-app-manifest+json
    application/xhtml+xml
    application/xml
    font/opentype
    image/svg+xml
    image/x-icon
    text/css
    text/plain
    text/x-component;
```

### Connection Optimization
```nginx
# Keep-alive connections
keepalive_timeout 65;
keepalive_requests 100;

# Worker processes optimization
worker_processes auto;
worker_connections 1024;
worker_rlimit_nofile 2048;

# File handling
sendfile on;
tcp_nopush on;
tcp_nodelay on;
```

### Buffer Optimization
```nginx
# Client buffers
client_body_buffer_size 128k;
client_max_body_size 10m;
client_header_buffer_size 1k;
large_client_header_buffers 4 4k;

# Proxy buffers
proxy_buffering on;
proxy_buffer_size 128k;
proxy_buffers 4 256k;
proxy_busy_buffers_size 256k;
```

## Logging and Monitoring

### Custom Log Formats
```nginx
log_format main '$remote_addr - $remote_user [$time_local] "$request" '
                '$status $body_bytes_sent "$http_referer" '
                '"$http_user_agent" "$http_x_forwarded_for"';

log_format json escape=json '{'
    '"time_local":"$time_local",'
    '"remote_addr":"$remote_addr",'
    '"remote_user":"$remote_user",'
    '"request":"$request",'
    '"status": "$status",'
    '"body_bytes_sent":"$body_bytes_sent",'
    '"request_time":"$request_time",'
    '"http_referrer":"$http_referer",'
    '"http_user_agent":"$http_user_agent"'
'}';
```

### Conditional Logging
```nginx
# Only log errors and slow requests
map $status $loggable {
    ~^[23]  0;
    default 1;
}

access_log /var/log/nginx/access.log main if=$loggable;

# Log slow requests
access_log /var/log/nginx/slow.log main if=$slow;
map $request_time $slow {
    ~^0\.[0-4] 0;
    default 1;
}
```

### Status Monitoring
```nginx
# Nginx status module
location /nginx_status {
    stub_status on;
    allow 127.0.0.1;
    deny all;
}
```

## Advanced Features

### Server-Side Includes (SSI)
```nginx
location / {
    ssi on;
    root /var/www/html;
}
```

### URL Rewriting
```nginx
# Redirect old URLs
rewrite ^/old-page$ /new-page permanent;

# Remove file extensions
location / {
    try_files $uri $uri.html $uri/ =404;
}

# Pretty URLs
location ~ ^/user/([0-9]+)$ {
    rewrite ^/user/([0-9]+)$ /user.php?id=$1 last;
}
```

### Conditional Configuration
```nginx
# Geographic blocking
map $geoip_country_code $allowed_country {
    default yes;
    CN no;
    RU no;
}

server {
    if ($allowed_country = no) {
        return 403;
    }
}
```

### Microservices Routing
```nginx
# Route based on URI path
location /api/users/ {
    proxy_pass http://user-service/;
}

location /api/orders/ {
    proxy_pass http://order-service/;
}

location /api/payments/ {
    proxy_pass http://payment-service/;
}
```

## Common Use Cases

### WordPress Configuration
```nginx
server {
    listen 80;
    server_name wordpress.example.com;
    root /var/www/wordpress;
    index index.php;
    
    location / {
        try_files $uri $uri/ /index.php?$args;
    }
    
    location ~ \.php$ {
        fastcgi_pass unix:/var/run/php/php7.4-fpm.sock;
        fastcgi_index index.php;
        fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
        include fastcgi_params;
    }
    
    location ~* \.(js|css|png|jpg|jpeg|gif|ico|svg)$ {
        expires 1y;
        add_header Cache-Control "public, immutable";
    }
}
```

### SPA (Single Page Application)
```nginx
server {
    listen 80;
    server_name spa.example.com;
    root /var/www/spa/dist;
    index index.html;
    
    # Handle client-side routing
    location / {
        try_files $uri $uri/ /index.html;
    }
    
    # API proxy
    location /api/ {
        proxy_pass http://backend-api/;
    }
    
    # Static assets caching
    location ~* \.(js|css|png|jpg|jpeg|gif|ico|svg|woff|woff2)$ {
        expires 1y;
        add_header Cache-Control "public, immutable";
    }
}
```

### Docker Container Proxy
```nginx
upstream docker-app {
    server app1:3000;
    server app2:3000;
}

server {
    listen 80;
    server_name docker.example.com;
    
    location / {
        proxy_pass http://docker-app;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

## Troubleshooting

### Common Issues and Solutions

#### Configuration Test Fails
```bash
# Test configuration
sudo nginx -t

# Common issues:
# - Missing semicolons
# - Unclosed brackets
# - Invalid directive names
# - File permission issues
```

#### 502 Bad Gateway
```nginx
# Check upstream servers
upstream backend {
    server 127.0.0.1:3000 max_fails=1 fail_timeout=10s;
}

# Increase timeouts
proxy_connect_timeout 60s;
proxy_send_timeout 60s;
proxy_read_timeout 60s;
```

#### High Memory Usage
```nginx
# Optimize worker processes
worker_processes auto;
worker_rlimit_nofile 65535;

# Reduce buffer sizes
client_body_buffer_size 16k;
client_header_buffer_size 1k;
```

### Debugging Tools
```bash
# Check error logs
sudo tail -f /var/log/nginx/error.log

# Check access logs
sudo tail -f /var/log/nginx/access.log

# Check nginx status
sudo systemctl status nginx

# Check listening ports
sudo netstat -tlnp | grep nginx

# Check configuration
sudo nginx -T
```

## Learning Resources

### Official Documentation
- [Nginx Official Documentation](http://nginx.org/en/docs/)
- [Nginx Admin Guide](https://docs.nginx.com/nginx/admin-guide/)

### Books
- "Nginx HTTP Server" by Clément Nedelcu
- "Nginx High Performance" by Rahul Sharma
- "Mastering Nginx" by Dimitri Aivaliotis

### Online Courses
- Nginx Fundamentals on various platforms
- Linux Academy Nginx courses
- Udemy Nginx courses

### Community Resources
- [Nginx Forum](https://forum.nginx.org/)
- [Stack Overflow Nginx tag](https://stackoverflow.com/questions/tagged/nginx)
- [Reddit r/nginx](https://www.reddit.com/r/nginx/)

### Configuration Generators
- [NGINXConfig](https://nginxconfig.io/)
- [Mozilla SSL Configuration Generator](https://ssl-config.mozilla.org/)

### Testing Tools
- [SSL Labs SSL Test](https://www.ssllabs.com/ssltest/)
- [Security Headers](https://securityheaders.com/)
- Apache Bench (ab) for load testing
- wrk for HTTP benchmarking

## Practice Exercises

1. **Basic Setup**: Install Nginx and serve a simple HTML page
2. **Virtual Hosts**: Configure multiple domains on one server
3. **Reverse Proxy**: Proxy requests to a Node.js application
4. **Load Balancing**: Set up load balancing between multiple backend servers
5. **SSL Configuration**: Implement HTTPS with Let's Encrypt
6. **Caching**: Configure proxy caching for better performance
7. **Security**: Implement rate limiting and security headers
8. **Monitoring**: Set up logging and monitoring solutions

## Conclusion

Nginx is a powerful and flexible web server that can handle various tasks from serving static content to complex load balancing scenarios. This guide provides a solid foundation, but continuous practice and exploration of advanced features will help you master Nginx configuration and optimization.

Remember to always test your configurations in a development environment before applying them to production, and keep your Nginx installation updated for security and performance improvements.