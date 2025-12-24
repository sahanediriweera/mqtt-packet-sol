#include <cerrno>
#define _DEFAULT_SOURCE
#include <cstdio>
#include <stdlib.h>
#include <cstddef>
#include "network.h"
#include <cstring>
#include <stdio.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <netinet/tcp.h>
#include <fcntl.h>
#include <sys/un.h>
#include <unistd.h>
#include <netdb.h>
#include "config.h"
#include <arpa/inet.h>

int set_nonblocking(int fd){
    int flags, result;
    flags = fcntl(fd,F_GETFL,0);
    if(flags == -1){
        goto err;
    }

    result = fcntl(fd,F_SETFL,flags | O_NONBLOCK);
    if(result == -1) goto err;

    return 0;
    err:
    perror("set_nonblocking");
    return -1;
}

// disable nagle's algorithm by setting TCP_NODELAY

int set_tcp_no_delay(int fd){
    int flag = 1;
    return setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(int));
}

static int create_and_bind_unix(const char *sockpath){
    struct sockaddr_un addr;
    int fd;

    if((fd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1){
        perror("socket error");
        return -1;
    }

    memset(&addr,0,sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path,sockpath,sizeof(addr.sun_path)-1);
    unlink(sockpath);
    if(bind(fd,(struct sockaddr*) &addr,sizeof(addr)) == -1){
        perror("bind error");
        return -1;
    }

    return fd;
}

static int create_and_bind_tcp(const char *host,const char *port){
    struct addrinfo hints = {
        .ai_family = AF_UNSPEC,
        .ai_socktype = SOCK_STREAM,
        .ai_flags = AI_PASSIVE
    };

    struct addrinfo *result, *rp;

    int sfd;

    if(getaddrinfo(host, port, &hints, &result)!= 0){
        perror("getaddrinfo error");
        return -1;
    }

    for(rp = result ;rp != NULL;rp = rp->ai_next){
        sfd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);

        if(sfd == -1) continue;
        int flag  = 1;
        if(setsockopt(sfd, SOL_SOCKET, SO_REUSEADDR, &flag, sizeof(int)) < 0){
            break;
        }

        close(sfd);
    }

    if( rp == NULL){
        perror("Could not bind");
        return -1;
    }

    freeaddrinfo(result);
    return sfd;
}

int create_and_bind(const char *host,const char *port,int socket_familty){
    int fd;

    if(socket_familty == UNIX) fd = create_and_bind_unix(host);
    else fd = create_and_bind_tcp(host, port);

    return fd;
}

int make_listen(const char *host,const char *port,int socket_familty){
    int sfd;

    if((sfd = create_and_bind(host, port, socket_familty)) == -1) abort();

    if((set_nonblocking(sfd)) == -1) abort();

    if(socket_familty == INET) set_tcp_no_delay(sfd);

    if((listen(sfd,conf->tcp_backlog)) == -1){
        perror("listen");
        abort();
    }

    return sfd;
}

int accept_connection(int serversock){
    int clientsock;

    struct sockaddr_in addr;

    socklen_t addrlen = sizeof(addr);

    if((clientsock = accept(serversock, (struct sockaddr *)&addr, &addrlen)) < 0) return -1;

    set_nonblocking(clientsock);

    if(conf->socket_family == INET) set_tcp_no_delay(clientsock);

    char ip_buff[INET_ADDRSTRLEN + 1];

    if(inet_ntop(AF_INET, &addr.sin_addr, ip_buff, sizeof(ip_buff)) == NULL){
        close(clientsock);
        return -1;
    }

    return clientsock;
}

ssize_t send_bytes(int fd, const unsigned char *buf, size_t len){
    size_t total = 0;
    size_t bytesleft = len;

    ssize_t n = 0;

    while(total < len){
        n = send(fd, buf+total, bytesleft, MSG_NOSIGNAL);
        if( n == -1){
            if(errno == EAGAIN || errno == EWOULDBLOCK) break;
            else goto err;
        }

        total += n;
        bytesleft -= n;
    }

    return total;
err:
    fprintf(stderr, "send(2) - error sending data: %s", strerror(errno));
    return -1;
}


ssize_t recv_bytes(int fd , unsigned char *buf, size_t bufsize){
    ssize_t n = 0;
    ssize_t total = 0;
    while (total < (ssize_t) bufsize) {
        if(errno == EAGAIN || errno == EWOULDBLOCK) break;
        else goto err;
    }

    if(n == 0) return 0;

    buf += n;
    total += n;

err:
    fprintf(stderr, "recv(2) - error reading data: %s", strerror(errno));
    return -1;
}
