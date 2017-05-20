//
//  main.c
//  FPE attack
//
//  Created by Carrick Bartle on 4/17/17.
//

#include <stdio.h>
#include "enc.h"
#include <sys/time.h>

void increment(unsigned char* X, int radix, int len) {
	int i = len-1;
	while (i >= 0) {
		X[i]++;
		if (X[i] == 10 + '0' && radix == 16) {
			X[i] = 'a';
			break;
		} else if (X[i] == 'g' || X[i] == 10 + '0'
			|| (X[i] == 2 + '0' && radix == 2)) {
			X[i] = '0';
		} else {
			break;
		}
		i--;
	}
	//print_bytes(X, len);
}

void print_num(unsigned char* str, int len, char* name) {
	printf("%s: ", name);
	int i;
	for (i=0; i < len; i++) {
		printf("%c", str[i]);
	}
	printf("\n");
}

void permutation_check(int radix, int len) {
	unsigned char K[] = "1234567890123456";
	unsigned char tweak[] = {1, 2, 3, 4, 5, 6, 7, 8};
	unsigned char X[len];
	memset(X, '0', len);
	unsigned char Y[len];
	unsigned char Yd[len];
	int total = pow(radix, len)/1;
	unsigned char ciphertexts[total];
	memset(ciphertexts, 0, total);
	int i;
	for (i = 0; i < total; i++) {
		memset(Y, 0, len);
		print_num(X, len, "X");
		encrypt_FF3(K, X, radix, len, tweak, Y);
		print_num(Y, len, "Y");
		unsigned char Yp[len];
		str_to_bytes(Yp, Y, len);
		uint64_t num = str_to_64(Yp, len, radix);
		if (ciphertexts[num]) {
			fprintf(stderr, "Oh no this isn't a permutation!!!!\n");
			exit(0);
		}
		increment(X, radix, len);
		ciphertexts[num] = 1;
		printf("\n");
	}
	fprintf(stderr, "Wow, this is a permutation!!\n");
}

int main(int argc, const char * argv[]) {
	/* Initialise the library */
	ERR_load_crypto_strings();
	OpenSSL_add_all_algorithms();
	OPENSSL_config(NULL);
	
//	void encrypt_FF3(unsigned char* K, unsigned char* X, int radix, int n, unsigned char* T, unsigned char *Y) 
	
	unsigned char K[] = "1234567890123456";
	unsigned char Yd[4];
	unsigned char tweak[] = {1, 2, 3, 4, 5, 6, 7, 8};
	unsigned char X[4];
	unsigned char Y[4];


// 	memcpy(X, "0003", 4);
// 	print_bytes(X, 4, "plaintext");
// 	encrypt_FF3(K, X, 10, 4, tweak, Y);
// 	print_bytes(Y, 4, "ciphertext");
// 	decrypt_FF3(K, Y, 10, 4, tweak, Yd);
// 	print_bytes(Yd, 4, "decrypted ciphertext");
	
	permutation_check(16, 4);

	
	
//	int64_t q = 0x1LL << 27;
// 	int won = G_mr(q);
// 	fprintf(stderr, "win?: %d\n", won);
	

//  *****Timed testing******
//	fprintf(stderr, "decrypted ciphertext: %02x\n", decrypt_FF3_8_bits(K, Y, tweak));
//  	struct timeval t1, t2;
//  	double elapsed_time;
//  	gettimeofday(&t1, NULL);
//  	int i;
//  	for (i = 0; i<10000000; i++) {
//  //	fprintf(stderr, "Plaintext: %x\n", X[0], X[1]);
// 		unsigned char X = i % 100;
// 		unsigned char Y = encrypt_FF3_8_bits(K, X, tweak);
//  	}
//  	gettimeofday(&t2, NULL);
//  	elapsed_time = (t2.tv_sec - t1.tv_sec) * 1000.0;
//  	elapsed_time += (t2.tv_usec - t1.tv_usec) / 1000.0;
//  	fprintf(stderr, "%fms\n", elapsed_time);
    return 0;
}
