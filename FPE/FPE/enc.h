#pragma once

#ifndef ENC_H
#define ENC_H

#define FF3_T_LEN 8


#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <string.h>
#include <math.h>


unsigned char* X;
unsigned char* Xp;
unsigned char* K;

void p(unsigned char num, char* name);
void encrypt_FF3(unsigned char* K, unsigned char* X, int radix, int n, unsigned char* T, unsigned char *Y);
void decrypt_FF3(unsigned char* K, unsigned char* X, int radix, int n, unsigned char* T, unsigned char *Y);
int G_mr(uint64_t q, int radix, int len);
void print_bytes(unsigned char *mem, int size, char* name);
void str_to_bytes(unsigned char * buf, unsigned char* str, int len);

#endif