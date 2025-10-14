#include <cstddef>
#include <cstdint>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "mqtt.h"
#include "pack.h"

static size_t unpack_mqtt_connect(const unsigned char*,union mqtt_header*,union mqtt_packet *); 
static size_t unpack_mqtt_publish(const unsigned char *,union mqtt_header *, union mqtt_packet *);
static size_t unpack_mqtt_subscribe(const unsigned char *,union mqtt_header *,union mqtt_packet *);
static size_t unpack_mqtt_unsubscribe(const unsigned char *,union mqtt_header *,union mqtt_packet *);
static size_t unpack_mqtt_ack(const unsigned char *,union mqtt_header *,union mqtt_packet *);
static unsigned char *pack_mqtt_header(const union mqtt_header *);
static unsigned char *pack_mqtt_ack(const union mqtt_packet *);
static unsigned char *pack_mqtt_connack(const union mqtt_packet *);
static unsigned char *pack_mqtt_suback(const union mqtt_packet *);
static unsigned char *pack_mqtt_publish(const union mqtt_packet *);

static const int MAX_LEN_BYTES = 4;

int mqtt_encode_length(unsigned char *buf,size_t len){
  int bytes = 0;

  do {

    if(bytes + 1 >  MAX_LEN_BYTES){
      return bytes;
    }

    short d = len%128;

    len /= 128;
    if(len > 0){
      d |= 128;
      buf[bytes++] = d;
    }

  } while ( len > 0);

  return bytes;
}

unsigned long long mqtt_decode_length(const unsigned char **buf){
  char c;
  int multiplier  = 1;
  unsigned long long value = 0LL;
  do {
    c = **buf;
    value += (c&127)*multiplier;
    multiplier *= 128;
    (*buf)++;
  } while((c&128)!=0);
  return value;
}

static size_t unpack_mqtt_connect(const unsigned char *buf, union mqtt_header *hdr, union mqtt_packet *pkt){
  struct mqtt_connect connect = {.header = *hdr};
  pkt->connect = connect;
  const unsigned char *init = buf;

  size_t len = mqtt_decode_length(&buf);

  buf = init + 8;

  pkt->connect.byte = unpack_u8((const uint8_t **)&buf);
  pkt->connect.payload.keepalive = unpack_u16((const uint8_t **)&buf);
  uint16_t cid_len = unpack_u16((const uint8_t **)&buf);

  if(cid_len > 0){
    pkt->connect.payload.client_id = (unsigned char *) malloc(cid_len + 1);
    unpack_bytes((const uint8_t **) &buf, cid_len, pkt->connect.payload.client_id);
  }

  if(pkt->connect.bits.will == 1){
    unpack_string16(&buf, &pkt->connect.payload.will_topic);
    unpack_string16(&buf, &pkt->connect.payload.will_topic);
  }

  if(pkt->connect.bits.username == 1){
    unpack_string16(&buf, &pkt->connect.payload.username);
  }

  if(pkt->connect.bits.password == 1){
    unpack_string16(&buf,&pkt->connect.payload.password);
  }

  return len;
}

static size_t unpack_mqtt_publish(const unsigned char *buf, union mqtt_header *hdr,union mqtt_packet *pkt){
  struct mqtt_publish publish = {.header = *hdr};
  pkt->publish = publish;

  size_t len = mqtt_decode_length(&buf);

  uint16_t topic_len = unpack_u16((const uint8_t **)&buf);
  pkt->publish.topiclen = unpack_string16(&buf, &pkt->publish.topic);
  uint16_t message_len = len;

  if(publish.header.bits.qos > AT_MOST_ONCE){
    pkt->publish.pkt_id = unpack_u16((const uint8_t **)&buf);
    message_len -= sizeof(uint16_t);
  }

  message_len -= (sizeof(uint16_t)+topic_len);

  pkt->publish.payloadlen = &message_len;
  pkt->publish.payload = (unsigned char *) malloc(message_len + 1);
  unpack_bytes((const uint8_t **)&buf,message_len, pkt->publish.payload);
  return len;
}
