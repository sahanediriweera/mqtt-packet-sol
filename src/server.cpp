#include "network.h"
#include "pack.h"
#include "util.h"
#include <cstdint>
#include <cstdio>
#include <ctime>
#define _POSIX_C_SOURCE 200809L
#include <cstddef>
#include <cstdlib>
#include <sys/socket.h>
#include "server.h"
#include "mqtt.h"
#include <netinet/in.h>
#include <string.h>
#include <arpa/inet.h>

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


struct connection {
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

    char ip_buff[INET_ADDRSTRLEN + 1];

    if(inet_ntop(AF_INET, &addr.sin_addr, ip_buff,sizeof(ip_buff)) == NULL) return -1;

    struct sockaddr_in sin;

    socklen_t sinlen = sizeof(sin);

    if(getsockname(fd, (struct sockaddr *)&sin, &sinlen) < 0) return -1;

    conn->fd = clientsock;

    strcpy(conn->ip,ip_buff);

    return 0;
}

static void on_accept(struct evloop *loop, void *arg){
    struct closure *server = (closure *) arg;

    struct connection conn;

    accept_new_client(server->fd, &conn);

    struct closure *client_closure = (closure *) malloc(sizeof(*client_closure));

    if(!client_closure) return;
}

static ssize_t recv_packet(int clientfd,unsigned char *buf,char *command){
    ssize_t nbytes = 0;

    if((nbytes = recv_bytes(clientfd,buf,1))<=0){
        return -ERRCLIENTDC;

        unsigned char byte = *buf;
        buf++;
        if(DISCONNECT < byte || CONNECT > byte){
            return -ERRPACKETERR;
        }

        unsigned char buff[4];

        int count = 0;
        int n = 0;

        do {
            if((n = recv_bytes(clientfd,buf+count,1))<=0){
                return -ERRCLIENTDC;
            }

            buff[count] = buf[count];
            nbytes += n;
        } while(buff[count++] & (1<<7));

        const unsigned char *pbuf = &buff[0];
        unsigned long long tlen = mqtt_decode_length(&pbuf);

        if(tlen > conf->max_request_size){
            nbytes = -ERRMAXREQSIZE;
            goto exit;
        }

        if((n=recv(clientfd,buf+1,tlen))<0){
            goto err;
        }

        nbytes += n;
        *command = byte;
exit:
        return nbytes;
err:
        shutdown(clientfd);
        close(clientfd);
        return nbytes;
    }
}

static void on_read(struct evloop *loop,void *arg){
    struct closure *cb = arg;

    unsigned char *buffer = malloc(conf->max_request_size);

    if(!buffer){
        sol_error("Out of memory");
        goto errdc;
    }

    ssize_t bytes = 0;
    char command = 0;

    bytes = recv_packet(cb->fd,buffer,&command);

    if(bytes == -ERRCLIENTDC || bytes == -ERRMAXREQSIZE) {
        goto exit;
    }

    if(bytes == -ERRPACKETERR) goto errdc;

    info.bytes_recv++;

    union mqtt_packet packet;
    unpack_mqtt_packet(buffer,&packet);
    union mqtt_header hdr = {.byte = (unsigned char)(command)};

    int rc = handlers[hdr.bits.type](cb,&packet);

    if(rc == REARM_W){
        cb->call = on_write;

        evloop_rearm_callback_write(loop, cb);
    }else if(rc == REARM_R){
        cb->call = on_read;
        evloop_rearm_callback_read(loop,cb);
    }

exit:
    free(buffer);
    return;
errdc:
    free(buffer);
    sol_error("Dropping client");
    shutdown(cb->fd,0);
    close(cb->fd);
    hashtable_del(sol.clients,((struct sol_client *)cb->obj)->client_id);
    hashtable_del(sol.closures,cb->closure_id);
    info.nclients--;
    info.nconnections--;
    return;
}

static void on_write(struct evloop *loop,void *arg){
    struct closure *cb = arg;
    ssize_t sent;

    if((sent = send_bytes(cb->fd,cb->payload->data,cb->payload->size))<0){
        sol_error("Error writing on socket client %s: %s",((struct sol_client*)cb->obj)->client_id,strerror(errono));
    }


    info.bytes_sent += sent;
    bytestring_release(cb->payload);
    cb->payload = NULL;

    cb->call = on_read;

    evloop_rearm_callback_read(loop,cb);
}

#define SYS_TOPIC 14

static const char *sys_topic[SYS_TOPIC] = {
    "$SOL",
    "$SOL/broker/clients/",
    "$SOL/broker/bytes/",
    "$SOL/broker/messages/",
    "$SOL/broker/uptime/",
    "$SOL/broker/uptime/sol",
    "$SOL/broker/clients/connected/",
    "$SOL/broker/clients/disconnected/",
    "$SOL/broker/bytes/sent/",
    "$SOL/broker/bytes/received/",
    "$SOL/broker/messages/sent/",
    "$SOL/broker/messages/received/",
    "$SOL/broker/memory/used"
};

static void run(struct evloop *loop){
    if(evloop_wait(loop)<0){
        sol_error("Event loop exited unexpectedly :%s", strerror(loop->status));
        evloop_free(loop);
    }
}

static int client_destructor(struct hastable_entry *entry){
    if(!entry) return -1;

    struct sol_client *client = entry->val;

    if(client->client_id) free(ient->client_id);
    free(client);
    return 0;
}

static int closure_destructor(struct hashtable_entry *entry){
    if(!entry) return -1;

    struct closure *closure = entry->val;
    if(closure->payload) bytestring_release(closure->payload);
    free(closure);
    return 0;
}

int start_server(const char *addr,const char *port){
    trie_init(&sol.topics);
    sol.clients = hashtable_create(client_destructor);
    sol.closures = hashtable_create(closure_destructor);

    struct closure server_closure;

    server_closure.fd = make_listen(addr,port,conf->socket_family);
    server_closure.payload = NULL;
    server_closure.args = &server_closure;
    server_closure.call = on_accept;
    generate_uuid(server_closure.closure_id);

    for(int i = 0;i < SYS_TOPIC;i++){
        sol_topic_put(&sol,topic_create(strdup(sys_topic[i])));
    }

    struct evloop *event_loop = evloop_create(EPOLL_MAX_EVENTS,EPOLL_TIMEOUT);

    evloop_add_callback(event_loop,&server_closure);

    struct closure sys_closure = {
        .fd = 0,
        .payload = NULL,
        .args = &sys_closure,
        .call = publish_stats
    };

    generate_uuid(sys_closure.closure_id);

    evloop_add_periodic_task(event_loop,conf->stats_pub_interval,0,&sys_closure);

    sol_info("Server start");
    info.start_time = time(NULL);
    run(event_loop);
    hastable_release(sol.clients);
    hastable_release(sol.closures);

    sol_info("Sol v%s exiting",VERSION);
    return 0;
}

static void publish_message(
        unsigned short pkt_id,
        unsigned short topiclen,
        const char *topic,
        unsigned short payloadlen,
        unsigned char *payload
        ){
    struct topic *t = sol_topic_get(&sol,topic);

    if(!t) return;

    union mqtt_packet pkt;
    struct mqtt_publish *p = mqtt_packet_publish(PUBLISH_BYTE, pkt_id, topiclen, (unsigned char *) topic, payloadlen, payload);

    pkt.publish = *p;
    size_t len;

    unsigned char *packed;

    struct list_node *cur = t->subscribers->head;
    size_t sent  = 0L;

    for(; cur;cur = cur->next){
        sol_debug("Sending PUBLISH (d%i, q%u, r%i,m%u,%s,... (%i bytes))",
                pkt.publish.header.bits.dup,
                pkt.publish.header.bits.qos,
                pkt.publish.header.bits.retain,
                pkt.publish.pkt_id,
                pkt.publish.topic,
                pkt.publish.payloadlen
                );
        len = MQTT_HEADER_LEN + sizeof(uint16_t) + pkt.publish.topiclen + pkt.publish.payloadlen;
        struct subscribers *sub = cur->data;
        struct sol_client *sc = sub->client;

        pkt.publish.header.bits.qos = sub->qos;
        if(pkt.publish.header.bits.qos > AT_MOST_ONCE) len += sizeof(uint16_t);
        int remaininglen_offset = 0;
        if((len-1) > 0x4000) remaininglen_offset = 3;
        else if((len-1) > 0x4000) remaininglen_offset = 2;
        else if((len-1) > 0x80) remaininglen_offset = 1;

        len += remaininglen_offset;

        packed = pack_mqtt_packet(&pkt, PUBLISH);
        if((sent = send_bytes(sc->fd, packed, len)) < 0){
            sol_error("Error publishing to %s: %s",sc->client_id,strerror(errono));
        }


        info.bytes_sent += sent;
        info.messages_sent++;
        free(packed);
    }
    free(p);
}

static void publish_stats(struct evloop *loop,void *args){
    char cclients[number_len(info.clients) + 1];
    sprintf(clients, "%d",info.nclients);
    char bsent[number_len(info.bytes_sent)+1];
    sprintf(bsent, "%lld", info.bytes_sent);
    char msent[number_len(info.messages_sent)+1];
    sprintf(msent, "%lld", info.messages_sent);
    char mrecv[number_len(info.messages_recv) +1];
    sprintf(mrecv, "%lld", info.messages_recv);
    long long uptime = time(NULL) - info.start_time;
    char utime[number_len(uptime) + 1]
        sprintf(utime, "%lld",uptime);
    double sol_uptime = (double) (time(NULL)-info.start_time) / SOL_SECONDS;

    char sutime[16];
    sprintf(sutime,"%.4f",sol_uptime);
    publish_message(0, strlen(sys_topic[5]), sys_topic[5], strlen(utime), (unsigned char *) &utime);
    publish_message(0, strlen(sys_topic[6]), sys_topic[6], strlen(sutime), (unsigned char *) &sutime);
    publish_message(0, strlen(sys_topic[7]), sys_topic[7], strlen(cclients), (unsigned char *) &cclients);
    publish_message(0, strlen(sys_topic[9]), sys_topic[9], strlen(bsent), (unsigned char *) &bsent);
    publish_message(0, strlen(sys_topic[11]), sys_topic[11], strlen(msent), (unsigned char *) &msent);
    publish_message(0, strlen(sys_topic[12]), sys_topic[12], strlen(mrecv), (unsigned char *) &mrecv);
}
