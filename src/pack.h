#ifndef PACK_H
#define PACK_H

#include <cstddef>
#include <cstdint>
#include <stdio.h>

uint8_t unpack_u8(const uint8_t **);
uint16_t unpack_u16(const uint8_t **);
uint32_t unpack_u32(const uint8_t **);
uint8_t *unpack_bytes(const uint8_t **,size_t,uint8_t *);
uint16_t unpack_string16(const uint8_t **buf,uint8_t **dest);

void pack_u8(uint8_t **,uint8_t);
void pack_u16(uint8_t   **,uint16_t);
void pack_u32(uint8_t **,uint32_t);
void pack_bytes(uint8_t **,uint8_t *);

struct byte_string{
    size_t size;
    size_t last;

    unsigned char* data;
};

struct bytestring *bytestring_create(size_t);
void byte_string_init(struct bytestring *,size_t);
void bytestring_release(struct bytestring *);
void bytestring_reset(struct bytestring *);

#endif // !PACK_H
