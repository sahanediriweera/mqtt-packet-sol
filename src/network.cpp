#include <cerrno>
#include <cstdlib>
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
#include <sys/epoll.h>

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

#define EVLOOP_INITIAL_SIZE 4

void evloop_init(struct evloop *loop,int max_events,int timeout){
    loop->max_events = max_events;
    loop->events = malloc(sizeof(struct epoll_event)*max_events);
    loop->epollfd = epoll_create1(0);
    loop->timeout = timeout;
    loop->periodic_maxsize = EVLOOP_INITIAL_SIZE;
    loop->periodic_nr = 0;
    loop->periodic_tasks = malloc(EVLOOP_INITIAL_SIZE * sizeof(*loop->periodic_tasks));
    loop->status = 0;
}

struct evloop *evloop_create(int max_events, int timeout){
    struct evloop *loop = (evloop *) malloc(sizeof(*loop));
    evloop_init(loop,max_events,timeout);
    return loop;
}

void evloop_free(struct evloop *loop){
    free(loop->events);
    for(int i =0;i < loop->periodic_nr;i++){
        free(loop->periodic_tasks[i]);
    }
    free(loop->periodic_tasks);
    free(loop);
}

int epoll_add(int efd, int fd, int evs, void *data){
    struct epoll_event ev;
    ev.data.fd = fd;

    if(data) ev.data.ptr = data;

    ev.events = evs | EPOLLET | EPOLLONESHOT;
    return epoll_ctl(efd,EPOLL_CTL_ADD,fd,&ev);;
}

int epoll_mod(int efd, int fd, int evs, void *data){
    struct epoll_event ev;

    ev.data.fd = fd;

    if(data) ev.data.ptr = data;
    ev.events = evs | EPOLLET | EPOLLONESHOT;

    return epoll_ctl(efd, EPOLL_CTL_MOD, fd, &ev);
}

int epoll_del(int efd, int fd){
    return epoll_ctl(efd, EPOLL_CTL_DEL,fd,NULL);
}

void evloop_add_callback(struct evloop *loop, struct closure *cb){
    if(epoll_add(loop->epollfd, cb->fd, EPOLLIN, cb) < 0) perror("Epoll register callback: ");
}

void evloop_add_periodic_task(struct evloop *loop, int seconds, unsigned long long ns, struct closure *cb){
    struct itimerspec timervalue;

    int timerfd = timerfd_create(CLOCK_MONOTONIC,0);
    memset(&timevalue, 0x00, sizeof(timervalue));

    timervalue.it_value.tv_sec = seconds;
    timervalue.it_value.tv_nsec = ns;
    timervalue.it_interval.tv_sec = seconds;
    timervalue.it_interval.tv_nsec = ns;
    if(timerfd_settime(timerfd, 0, &timervalue,NULL) < 0){
        perror("epoll_ctl(2): EPOLLIN");
        return;
    }

    if(loop->periodic_nr + 1 > loop->periodic_maxsize){
        loop->periodic_maxsize *= 2;
        loop->periodic_tasks = realloc(loop->periodic_tasks, loop->periodic_maxsize * sizeof(*loop->periodic_tasks));
    }

    loop->periodic_tasks[loop->periodic_nr] = malloc(sizeof(*loop->periodic_tasks[loop->periodic_nr]));
    loop->periodic_tasks[loop->periodic_nr]->closure = cb;
    loop->periodic_tasks[loop->periodic_nr]->timerfd = timerfd;
    loop->periodic_nr++;
}

int evloop_wait(struct evloop *el){
    int rc = 0;
    int events = 0;
    long int timer = 0L;
    int periodic_done = 0;

    while (1) {
        events = epoll_wait(el->epollfd,el->events, el->max_events, el->timeout);

        if(events < 0) {
            if(errono == EINTR) continue;

            rc -= -1;
            el->status = errono;
            break;
        }

        for (int i =0; i < events; i++) {
            if((el->events[i].events & EPOLLERR) ||
                (el->events[i].events & EPOLLHUP) ||
                (!(el->events[i].events & EPOLLIN) && !(el->events[i].events & EPOLLOUT))
            ){
                perror("epoll_wait(2)");
                shutdown(el->events[i].data.fd, 0);
                close(el->events[i].data.fd);
                el->status = errno;
                continue;
            }

            struct closure *closure = el->events[i].data.ptr;
            periodic_done = 0;
            for(int i =0;i< el->periodic_nr && periodic_done == 0;i++){
                if(el->events[i].data.fd == el->periodic_tasks[i]->timerfd){
                    struct closure *c = el->periodic_tasks[i]->closure;
                    (void) read(el>events[i].data.fd, &timer, 8);
                    c->call(el,c->args);
                    periodic_done = 1;
                }
            }

            if(periodic_done == 1) continue;

            closure->call(el,closure->args);
        }
    }

    return rc;
}

int evloop_rearm_callback_read(struct evloop *el, struct closure *cb){
    return epoll_mod(el->epollfd,cb->fd,EPOLLIN,cb);
}

int evloop_rearm_callback_write(struct evloop *el, struct closure *cb){
    return epoll_mod(el->epollfd, cb->fd, EPOLLOUT, cb);
}

int evloop_del_callback(struct evloop *el, struct closure *cb){
    return epoll_del(el->epollfd, cb->fd);
}
