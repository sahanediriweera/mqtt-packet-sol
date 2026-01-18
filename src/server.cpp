#include "network.h"
#include <cstddef>
#include <cstdlib>
#include <sys/socket.h>
#define _POSIX_C_SOURCE 200809L

static const double SOL_SECONDS = 88775.24;

static struct sol_info info;

static struct sol sol;

typedef int handler(struct closure *, union mqtt_packet *);

static int connect_handler(struct closure *, union mqtt_packet *);
static int disconnect_handler(struct closure *, union mqtt_packet *);
static int subscribe_handler(struct closure *, union mqtt_packet *);
static int unsubscribe_handler(struct closure *, union mqtt_packet *);
static int publish_handler(struct closure *, union mqtt_packet *);
static int puback_handler(struct closure *, union mqtt_packet *);
static int pubrec_handler(struct closure *, union mqtt_packet *);
static int pubrel_handler(struct closure *, union mqtt_packet *);
static int pubcomp_handler(struct closure *, union mqtt_packet *);
static int pingreq_handler(struct closure *, union mqtt_packet *);

static handler *handlers[15] = {
    nullptr,
    connect_handler,
    nullptr,
    publish_handler,
    puback_handler,
    pubrec_handler,
    pubrel_handler,
    pubcomp_handler,
    subscribe_handler,
    nullptr,
    unsubscribe_handler,
    nullptr,
    pingreq_handler,
    nullptr,
    disconnect_handler
};


struct connecction {
    char ip[INET_ADDRSTRLEN + 1];
    int fd;
};

static void on_read(struct evloop *, void *);
static void on_write(struct evloop *, void *);
static void on_accept(struct evloop *, void *);

static void publish_stats(struct evloop *,void *);

static int accept_new_client(int fd, struct connection *conn){

    if(!conn) return -1;

    int clientsock = accept_connection(fd);

    if(clientsock == -1) return -1;

    struct sockaddr_in addr;

    socklen_t addrlen = sizeof(addr);

    if(getpeername(clientsock, (struct sockaddr *)&addr, &addrlen) < 0) return -1;

    char ip_buff[INET_ADDSTRLEN + 1];

    if(inet_ntop(AF_INET, &addr.sin_addr, ip_buff,sizeof(ip_buff)) == NULL) return -1;

    struct sockaddr_in sin;

    socklen_t sinlen = sizeof(sin);

    if(getsockname(fd, (struct sockaddr *)&sin, &sinlen) < 0) return -1;

    conn->fd = clientsock;

    strcpy(conn->ip,ip_buff);

    return 0;
}

static void on_accept(struct evloop *loop, void *arg){
    struct closure *server = arg;

    struct connection conn;

    accept_new_client(server->fd, &conn);

    struct closure *client_closure = malloc(sizeof(*client_closure));

    if(!client_closure) return;
}
