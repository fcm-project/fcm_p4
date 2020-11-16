#include <x86intrin.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <algorithm>
#include <cstring>
#include <math.h>
#include <pthread.h>
#include <zlib.h>

// width=32 poly=0x04c11db7 init=0xffffffff refin=false refout=false xorout=0x00000000 check=0x0376e6e7 residue=0x00000000 name="CRC-32/MPEG-2"
uint32_t crc32b(uint8_t *message, int l) {
   int i, j;
   uint32_t crc, msb;

   crc = 0xFFFFFFFF;
   for(i = 0; i < l; i++) {
      // xor next byte to upper bits of crc
      crc ^= (((uint32_t)message[i])<<24);
      for (j = 0; j < 8; j++) {    // Do eight times.
            msb = crc>>31;
            crc <<= 1;
            crc ^= (0 - msb) & 0x04C11DB7;
      }
   }
   return crc;         // don't complement crc on output
}


// width=32 poly=0x000000af init=0x00000000 refin=false refout=false xorout=0x00000000 check=0xbd0be338 residue=0x00000000 name="CRC-32/XFER"
uint32_t crc32_xfer(uint8_t *message, int l)
{
   int i, j;
   uint32_t crc, msb;

   crc = 0x00000000;
   for(i = 0; i < l; i++) {
      // xor next byte to upper bits of crc
      crc ^= (((uint32_t)message[i])<<24);
      for (j = 0; j < 8; j++) {    // Do eight times.
            msb = crc>>31;
            crc <<= 1;
            crc ^= (0 - msb) & 0x000000af;
      }
   }
   return crc;         // don't complement crc on output
}


// width=32 poly=0x814141ab init=0x00000000 refin=false refout=false xorout=0x00000000 check=0x3010bf7f residue=0x00000000 name="CRC-32/AIXM"
uint32_t crc32q(uint8_t *message, int l)
{
   int i, j;
   uint32_t crc, msb;

   crc = 0x0;
   for(i = 0; i < l; i++) {
      // xor next byte to upper bits of crc
      crc ^= (((uint32_t)message[i])<<24);
      for (j = 0; j < 8; j++) {    // Do eight times.
            msb = crc>>31;
            crc <<= 1;
            crc ^= (0 - msb) & 0x814141AB;
      }
   }
   return crc;         // don't complement crc on output
}


/************* CRC32C *********************/

#define POLY 0x82f63b78
static uint32_t crc32c_table[8][256];
static pthread_once_t crc32c_once_sw = PTHREAD_ONCE_INIT;
/* Construct table for software CRC-32C calculation. */
static void crc32c_init_sw(void)
{
    uint32_t n, crc, k;

    for (n = 0; n < 256; n++) {
        crc = n;
        crc = crc & 1 ? (crc >> 1) ^ POLY : crc >> 1;
        crc = crc & 1 ? (crc >> 1) ^ POLY : crc >> 1;
        crc = crc & 1 ? (crc >> 1) ^ POLY : crc >> 1;
        crc = crc & 1 ? (crc >> 1) ^ POLY : crc >> 1;
        crc = crc & 1 ? (crc >> 1) ^ POLY : crc >> 1;
        crc = crc & 1 ? (crc >> 1) ^ POLY : crc >> 1;
        crc = crc & 1 ? (crc >> 1) ^ POLY : crc >> 1;
        crc = crc & 1 ? (crc >> 1) ^ POLY : crc >> 1;
        crc32c_table[0][n] = crc;
    }
    for (n = 0; n < 256; n++) {
        crc = crc32c_table[0][n];
        for (k = 1; k < 8; k++) {
            crc = crc32c_table[0][crc & 0xff] ^ (crc >> 8);
            crc32c_table[k][n] = crc;
        }
    }
}

/* Table-driven software version as a fall-back.  This is about 15 times slower
   than using the hardware instructions.  This assumes little-endian integers,
   as is the case on Intel processors that the assembler code here is for. */
static uint32_t crc32c_sw(uint32_t crci, const uint8_t *buf, size_t len)
{
    const unsigned char *next = buf;
    uint64_t crc;

    pthread_once(&crc32c_once_sw, crc32c_init_sw);
    crc = crci ^ 0xffffffff;
    // crc = crci ^ 0x80000000;
    while (len && ((uintptr_t)next & 7) != 0) {
        crc = crc32c_table[0][(crc ^ *next++) & 0xff] ^ (crc >> 8);
        len--;
    }
    while (len >= 8) {
        crc ^= *(uint64_t *)next;
        crc = crc32c_table[7][crc & 0xff] ^
              crc32c_table[6][(crc >> 8) & 0xff] ^
              crc32c_table[5][(crc >> 16) & 0xff] ^
              crc32c_table[4][(crc >> 24) & 0xff] ^
              crc32c_table[3][(crc >> 32) & 0xff] ^
              crc32c_table[2][(crc >> 40) & 0xff] ^
              crc32c_table[1][(crc >> 48) & 0xff] ^
              crc32c_table[0][crc >> 56];
        next += 8;
        len -= 8;
    }
    while (len) {
        crc = crc32c_table[0][(crc ^ *next++) & 0xff] ^ (crc >> 8);
        len--;
    }
    return (uint32_t)crc ^ 0xffffffff;
    // return (uint32_t)crc ^ 0x80000000;
}

/*
To compiile this file, use the command
g++-5 hash_calc.cpp -lz -lpthread -o hash_calc
*/

int main()
{
  // hexidecimal, binary, decimal
	/*
	CRC32 value is : 408597
	crc32b : 465664
	CRC32c_sw value is: 161017
	*/
	// // 0xC0, 0xA8, 0x01, 0x01
	uint8_t bytes[4] = {192, 168, 1, 1};
	uint32_t crc = crc32(0L, Z_NULL, 0);
	for (int i = 0; i < 4; ++i){
	  crc = crc32(crc, bytes + i, 1);
	}
	printf("CRC32 value is : %lu\n", crc);

	/*** CRC32/mpeg2
    3215923968 -> 465664 (crc_32_mpeg) ***/
	uint8_t buffer[] = {192, 168, 1, 1}; 
	uint32_t result = crc32b(buffer, 4);
	printf("crc32b : %lu\n", result);

	/**** CRC32c test ******/
	uint32_t crc32c = crc32c_sw(0L, Z_NULL, 0);
	for (int i = 0; i < 4; ++i)
	    crc32c = crc32c_sw(crc32c, bytes + i, 1);
	printf("CRC32c_sw value is: %lu\n", crc32c);

}


