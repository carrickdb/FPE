//
//  main.c
//  FPE attack
//
//  Created by Carrick Bartle on 4/17/17.
//

#include <stdio.h>
#include "enc.h"
#include <sys/time.h>


int main(int argc, const char * argv[]) {
	/* Initialise the library */
	ERR_load_crypto_strings();
	OpenSSL_add_all_algorithms();
	OPENSSL_config(NULL);
	
	unsigned char K[] = "1234567890123456";
	unsigned char X = 0x25;
	unsigned char tweak[] = {1, 2, 3, 4, 5, 6, 7, 8};
	p(X, "plaintext");
	unsigned char Y = encrypt_FF3_8_bits(K, X, tweak);
	p(Y, "ciphertext");
	unsigned char Yd = decrypt_FF3_8_bits(K, Y, tweak);
	p(Yd, "decrypted ciphertext");
	
	int64_t q = 0x1LL << 27;
 	int won = G_mr(q);
 	fprintf(stderr, "win?: %d\n", won);
	
// 	int i;
// 	for (i = 0; i < 100; i++) {
// 		fprintf(stderr, "%d: ", i);
// 		unsigned char new_ciphertext = encrypt_FF3_8_bits(K, X, tweak);
// 		fprintf(stderr, "%02x\n", new_ciphertext);
// 		if (new_ciphertext == ciphertexts[i]) {
// 			fprintf(stderr, "OMG this isn't a permutation!!!!\n");
// 			return 0;
// 		}
// 		ciphertexts[i] = new_ciphertext;
// 		unsigned char tens = (i+1) / 10;
// 		unsigned char ones = (i+1) % 10;
// 		X = tens << 4;
// 		X |= ones;
// 	}
// 	fprintf(stderr, "Wow, this is a permutation!!");
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
