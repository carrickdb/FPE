#include "enc.h"

void handleErrors(void)
{
	ERR_print_errors_fp(stderr);
	abort();
}

int decrypt_CBC(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
	unsigned char *iv, unsigned char *plaintext)
{
	EVP_CIPHER_CTX *ctx;

	int len;

	int plaintext_len;

	/* Create and initialise the context */
	if (!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

	/* Initialise the decryption operation. IMPORTANT - ensure you use a key
	* and IV size appropriate for your cipher
	* In this example we are using 256 bit AES (i.e. a 256 bit key). The
	* IV size for *most* modes is the same as the block size. For AES this
	* is 128 bits */
	if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
		handleErrors();

	/* Provide the message to be decrypted, and obtain the plaintext output.
	* EVP_DecryptUpdate can be called multiple times if necessary
	*/
	if (1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
		handleErrors();
	plaintext_len = len;

	/* Finalise the decryption. Further plaintext bytes may be written at
	* this stage.
	*/
	if (1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) handleErrors();
	plaintext_len += len;

	/* Clean up */
	EVP_CIPHER_CTX_free(ctx);

	return plaintext_len;
}

int encrypt_CBC(unsigned char *plaintext, int plaintext_len, unsigned char *key,
	unsigned char *iv, unsigned char *ciphertext)
{
	EVP_CIPHER_CTX *ctx;

	int len;

	int ciphertext_len;

	/* Create and initialise the context */
	if (!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

	/* Initialise the encryption operation. IMPORTANT - ensure you use a key
	* and IV size appropriate for your cipher
	* In this example we are using 256 bit AES (i.e. a 256 bit key). The
	* IV size for *most* modes is the same as the block size. For AES this
	* is 128 bits */
	if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
		handleErrors();

	/* Provide the message to be encrypted, and obtain the encrypted output.
	* EVP_EncryptUpdate can be called multiple times if necessary
	*/
	if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
		handleErrors();
	ciphertext_len = len;

	/* Finalise the encryption. Further ciphertext bytes may be written at
	* this stage.
	*/
	if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) handleErrors();
	ciphertext_len += len;

	/* Clean up */
	EVP_CIPHER_CTX_free(ctx);

	return ciphertext_len;
}

int encrypt_ECB(unsigned char *plaintext, int plaintext_len, unsigned char *key,
	unsigned char *ciphertext)
{
	EVP_CIPHER_CTX *ctx;
	int len;
	int ciphertext_len;

	/* Create and initialise the context */
	if (!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

	if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, key, NULL))
		handleErrors();

	/* Provide the message to be encrypted, and obtain the encrypted output. */
	if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
		handleErrors();
	ciphertext_len = len;

	/* Clean up */
	EVP_CIPHER_CTX_free(ctx);

	return ciphertext_len;
}

void FF3firstversion() {
	/* An implementation of FF3 encryption for one byte (two decimal digits). */
	// unsigned char encrypt_FF3_8_bits(unsigned char* K, unsigned char X, unsigned char* T) {
	// 	// K = key; X = message; T = tweak (64 bits long)
	// 	int half_t_len = FF3_T_LEN/2;
	// 	unsigned char T_L[half_t_len];
	// 	memcpy(T_L, T, half_t_len);
	// 	unsigned char T_R[half_t_len];
	// 	memcpy(T_R, T+half_t_len, half_t_len);
	// 	unsigned char W[half_t_len];
	// 	unsigned char A = X >> 4;
	// 	unsigned char B = X & 0x0F;
	// 	int i;
	// 	for (i = 0; i < 8; i++) {
	// 		if (i%2 == 0) {
	// 			memcpy(W, T_R, half_t_len);
	// 		} else {
	// 			memcpy(W, T_L, half_t_len);
	// 		}
	// 		unsigned char _i[4];
	// 		int_to_bytes(_i, i, 4);		
	// 		unsigned char P[16];
	// 		unsigned char W_XOR_i[half_t_len];
	// 		XOR_bytes(W_XOR_i, W, _i, half_t_len);
	// 		memcpy(P, W_XOR_i, half_t_len);
	// 		unsigned char B_str[12];
	// 		memset(B_str, 0, 12);
	// 		B_str[11] = B;
	// 		memcpy(P+4, B_str, 12);
	// 		unsigned char P_rev[16];
	// 		reverse_bytes(P_rev, P, 16);
	// 		unsigned char K_rev[16];
	// 		reverse_bytes(K_rev, K, 16);
	// 		unsigned char S_rev[16];
	// //		print_hex_memory(P_rev, 16);
	// 		int ciphertext_len = encrypt_ECB(P_rev, 16, K_rev, S_rev);
	// //		print_hex_memory(S_rev, 16);
	// 		unsigned char S[16];
	// 		reverse_bytes(S, S_rev, 16);
	// 		unsigned char y_mod = S[15] % 10;
	// 		//fprintf(stderr, "y_mod: %x\n", y_mod);
	// 		unsigned char A_num_mod = A % 10;
	// 		//fprintf(stderr, "A_num_mod: %x\n", A_num_mod);
	// 		unsigned char c = (A_num_mod + y_mod) % 10;
	// 		A = B;
	// 		B = c; 
	// 	}
	// 	unsigned char Y = B;
	// //	fprintf(stderr, "A: %02x\n", A);
	// //	fprintf(stderr, "B: %02x\n", B);
	// 	Y = Y | (A << 4);
	//   	EVP_cleanup();
	// 	ERR_free_strings();
	// 	return Y;
	// }
	// 
	// /* An implementation of FF3 decryption for one byte (two decimal digits). */
	// unsigned char decrypt_FF3_8_bits(unsigned char* K, unsigned char X, unsigned char* T) {
	// 	// K = key; X = message; T = tweak (64 bits long); Y = buffer for decrypted message
	// 	unsigned char A = X >> 4;
	// 	unsigned char B = X & 0x0F;
	// 	int half_t_len = FF3_T_LEN/2;
	// 	unsigned char T_L[half_t_len];
	// 	memcpy(T_L, T, half_t_len);
	// 	unsigned char T_R[half_t_len];
	// 	memcpy(T_R, T+half_t_len, half_t_len);
	// 	unsigned char W[half_t_len];
	// 	int i;
	// 	for (i = 7; i >= 0; i--) {
	// 		if (i%2 == 0) {
	// 			memcpy(W, T_R, half_t_len);
	// 		} else {
	// 			memcpy(W, T_L, half_t_len);
	// 		}
	// 		unsigned char _i[4];
	// 		int_to_bytes(_i, i, 4);		
	// 		unsigned char P[16];
	// 		unsigned char W_XOR_i[half_t_len];
	// 		XOR_bytes(W_XOR_i, W, _i, half_t_len);
	// 		memcpy(P, W_XOR_i, half_t_len);
	// 		unsigned char A_str[12];
	// 		memset(A_str, 0, 12);
	// 		A_str[11] = A;
	// 		memcpy(P+4, A_str, 12);
	// 		unsigned char P_rev[16];
	// 		reverse_bytes(P_rev, P, 16);
	// 		unsigned char K_rev[16];
	// 		reverse_bytes(K_rev, K, 16);
	// 		unsigned char S_rev[16];
	// //		print_hex_memory(P_rev, 16);
	// 		int ciphertext_len = encrypt_ECB(P_rev, 16, K_rev, S_rev);
	// //		print_hex_memory(S_rev, 16);
	// 		unsigned char S[16];
	// 		reverse_bytes(S, S_rev, 16);
	// 		unsigned char y_mod = S[15] % 10;
	// 		unsigned char B_num_mod = B % 10;
	// 		int c = (B_num_mod - y_mod) % 10;
	// 		if (c < 0) {
	// 			c += 10;
	// 		}
	// 		B = A;
	// 		A = c;
	// 	}
	// 	unsigned char Y = B;
	// //	fprintf(stderr, "A: %02x\n", A);
	// //	fprintf(stderr, "B: %02x\n", B);
	// 	Y = Y | (A << 4);
	//   	EVP_cleanup();
	// 	ERR_free_strings();
	// 	return Y;
	// }
}

void print_bytes(unsigned char *mem, int size, char* name) {
	printf("%s: ", name);
	int i;
	for (i = 0; i < size; i++) {
		printf("%02x ", mem[i]);
	}
	printf("\n");
}

void int_to_bytes(unsigned char* buf, int num, int len) {
	int i;
	for (i = 0; i < len; i++) {
		buf[i] = (num >> (8 * (len - i - 1))) & 0xFF;
	}
}

void long_to_bytes(unsigned char* buf, long num, int len) {
	if (len > 4) {
		len = 4;
	}
	int i;
	for (i = 0; i < len; i++) {
		buf[i] = (num >> (8 * (len - i - 1))) & 0xFF;
	}
}

void int64_to_bytes(unsigned char* buf, uint64_t num, int len) {
	memset(buf, 0, len);
	int start = 0;
	if (len > 8) {
		start = len - 8;
	}
	int i;
	for (i = start; i < len; i++) {
		buf[i] = (num >> (8 * (len - i - 1))) & 0xFF;
	}
}

void p(unsigned char num, char* name) {
	fprintf(stderr, "%s: %02x\n", name, num);
}

/* An implementation of NIST FPE standard FF1. */
//void encrypt_FF1(char* m, int radix, const int m_len, unsigned char* tweak, int tweak_len) {
//	char c[m_len];
//	const int u = m_len / 2;
//	int v = m_len - u;
//	char L[u];
//	memcpy(L, m, u);
//	char R[v];
//	memcpy(R, m + u, v);
//	double b = log(radix) / log(2);
//	b = ceil(v*b);
//	b = ceil(b / 8.0);
//	int b_int = ceil(b / 4) / 1; // cieling(ceiling(8*(log base 2 of 10))/8) = 4
//	int d = b_int * 4 + 4;
//	fprintf(stderr, "%d\n", b_int);
//	unsigned char P[] = { 1, 2, 1, 0, 0, 0, 10, u % 256, 0, 0, 0, 0, 0, 0, 0, 0 };
//	int_to_bytes(P + 3, 0xFFFFFF, 3);
//	int_to_bytes(P + 8, m_len, 4);
//	int_to_bytes(P + 12, tweak_len, 4);
//	int rem = (-tweak_len - b_int - 1) % 16;
//	if (rem < 0) {
//		rem += 16;
//	}
//	int Q_len = tweak_len + rem + 1 + b_int;
//	fprintf(stderr, "%d\n", Q_len);
//	int i;
//	for (i = 0; i < 10; i++) {
//		unsigned char Q[Q_len];
//		memset(Q, 0, sizeof(Q));
//		memcpy(Q, tweak, tweak_len);
//		int_to_bytes(Q + tweak_len + rem, i, 1);
//		long R_long = atol(R);  // May need to make this longer
//		long_to_bytes(Q + tweak_len + rem + 1, R_long, 8);
//		//print_hex_memory(Q, sizeof(Q));
//	}
//}

void XOR_bytes(unsigned char* A_XOR_B, unsigned char *A, unsigned char *B, int len) {
	int i;
	for (i = 0; i < len; i++) {
		A_XOR_B[i] = A[i] ^ B[i];
	}
}

void reverse_bytes(unsigned char* rev_bytestr, unsigned char* bytestr, int len) {
	int i;
	for (i = 0; i < len / 2; i++) {
		rev_bytestr[i] = bytestr[len - i - 1];
		rev_bytestr[len - i - 1] = bytestr[i];
	}
	if (len % 2 != 0) {
		rev_bytestr[len / 2] = bytestr[len / 2];
	}
}

uint64_t str_to_64(unsigned char* str, int len, int radix) {
	// str assumed already converted to raw numbers from character string
	uint64_t num = 0;
	int i;
	for (i = 0; i<len; i++) {
		// 		printf("str: %d\n", str[i]);
		double radix_pow = pow(radix, len - i - 1);
		int radix_p = (int)radix_pow / 1;
		// 		printf("radix^pow: %f\n", radix_pow);
		// 		printf("radix^p: %d\n", radix_p);
		int total = str[i] * radix_p;
		// 		printf("%d\n", total);
		num += str[i] * radix_p;
		// 		printf("%lld\n", num);
	}
	return num;
}

uint64_t get_ymod(unsigned char* buf, int buflen, int m, int radix) {
	uint64_t ymod = 0;
	int radix_m = pow(radix, m) / 1;
	if ((radix == 2 || radix == 16) && radix_m < 256) {
		return buf[buflen - 1] % radix_m;
	}
	int seglen = 0;
	if (radix == 2) {
		// How many bits does it take to express radix_m?
		seglen = m;
	}
	else if (radix == 16) {
		seglen = m * 4;
	}
	if (radix == 2 || radix == 16) {
		int overflow = seglen % 8;
		int full_bytes = seglen / 8;
		//print_bytes(buf+buflen-full_bytes-1, 1, "buf");
		int mask = 0xFF;
		mask >>= 8 - overflow;
		ymod = buf[buflen - full_bytes - 1] & mask;
		full_bytes--;
		//printf("%lld\n", ymod);
		while (full_bytes >= 0) {
			ymod <<= 8;
			//printf("%lld\n", ymod);
			ymod |= buf[buflen - full_bytes - 1];
			//printf("%lld\n", ymod);
			full_bytes--;
		}
		//printf("y mod power of 2 or 16: %lld\n", ymod);
		return ymod;
	}
	// radix = 10
	int curr = buflen - 1;
	ymod = buf[curr] % radix_m;
	int twos_mod = 1;
	curr--;
	while (curr >= 0) {
		int i;
		twos_mod <<= 8;
		twos_mod %= radix_m;
		int bufmod = buf[curr] % radix_m;
		bufmod = (bufmod*twos_mod) % radix_m;
		ymod = (ymod + bufmod) % radix_m;
		curr--;
	}
	// 	printf("ymod: %lld\n", ymod);
	return ymod;
}

void int64_to_str(unsigned char* dest, int len, uint64_t num, int radix) {
	// Does not convert to ASCII.
	// Definitely working.
	memset(dest, 0, len);
	int curr = len - 1;
	while (curr >= 0) {
		dest[curr] = num % radix;
		num /= radix;
		curr--;
	}
}

void str_to_bytes(unsigned char* dest, unsigned char* src, int len) {
	// converts from ASCII
	int i;
	for (i = 0; i<len; i++) {
		if (src[i] < 58 && src[i] > 47) {
			dest[i] = src[i] - '0';
		}
		else if (src[i] > 96 && src[i] < 103) {
			dest[i] = src[i] - 87;
		}
		else {
			printf("Invalid character.\n");
		}
	}
}

void bytes_to_ascii(unsigned char* dest, unsigned char* src, int len) {
	int i;
	for (i = 0; i<len; i++) {
		if (src[i] < 10 && src[i] >= 0) {
			dest[i] = src[i] + '0';
		}
		else if (src[i] > 9 && src[i] < 16) {
			dest[i] = src[i] + 87;
		}
		else {
			printf("Byte cannot be converted to a valid character.\n");
		}
	}
}

void encrypt_FF3(unsigned char* K, unsigned char* X, int radix, int n, unsigned char* T, unsigned char *Y) {
	// K = key; X = message encoded as an ASCII string; radix = base, n = length of X, 
	// T = tweak (assumed to be 64 bits long), Y = buffer for ciphertext.
	// The integers that each half of X represents are assumed to be expressible in 64 bits or fewer.
	unsigned char* A;
	unsigned char* B;
	int u = ceil((double)n / 2.0) / 1;
	int v = n - u;
	A = malloc(u * sizeof(unsigned char));
	B = malloc(v * sizeof(unsigned char));
	str_to_bytes(A, X, u);
	str_to_bytes(B, X + u, v);
	// 	print_bytes(A, u, "A");
	// 	print_bytes(B, v, "B");	
	int half_t_len = FF3_T_LEN / 2;
	unsigned char T_L[half_t_len];
	memcpy(T_L, T, half_t_len);
	unsigned char T_R[half_t_len];
	memcpy(T_R, T + half_t_len, half_t_len);
	unsigned char W[half_t_len];
	int m;
	int i;
	for (i = 0; i < 8; i++) {
		// 		p(i, "i");
		if (i % 2 == 0) {
			m = u;
			memcpy(W, T_R, half_t_len);
		}
		else {
			m = v;
			memcpy(W, T_L, half_t_len);
		}
		unsigned char _i[half_t_len];
		int_to_bytes(_i, i, 4);
		unsigned char P[16];
		unsigned char W_XOR_i[half_t_len];
		XOR_bytes(W_XOR_i, W, _i, half_t_len);
		memcpy(P, W_XOR_i, half_t_len);
		unsigned char revB[n - m];
		reverse_bytes(revB, B, n - m);
		unsigned char num_str[12];
		uint64_t revB64 = str_to_64(revB, n - m, radix);
		int64_to_bytes(num_str, revB64, 12); // int to bytestring
		memcpy(P + 4, num_str, 12);
		unsigned char revP[16];
		reverse_bytes(revP, P, 16);
		unsigned char revK[16];
		reverse_bytes(revK, K, 16);
		unsigned char revS[16];
		int ciphertext_len = encrypt_ECB(revP, 16, revK, revS);
		if (ciphertext_len != 16) {
			fprintf(stderr, "Encryption failed.\n");
			exit(0);
		}
		unsigned char S[16];
		reverse_bytes(S, revS, 16);
		int radix_m = (int)pow(radix, m) / 1;
		unsigned char revA[m];
		reverse_bytes(revA, A, m);
		uint64_t revA64 = str_to_64(revA, m, radix);
		uint64_t ymod = get_ymod(S, 16, m, radix);
		uint64_t revA_mod = revA64 % radix_m;
		int c = (ymod + revA_mod) % radix_m;
		unsigned char revC[m];
		int64_to_str(revC, m, c, radix);
		unsigned char C[m];
		reverse_bytes(C, revC, m);
		free(A);
		A = malloc((n - m) * sizeof(unsigned char));
		memcpy(A, B, n - m);
		free(B);
		B = malloc(m * sizeof(unsigned char));
		memcpy(B, C, m);
	}
	bytes_to_ascii(Y, A, u);
	bytes_to_ascii(Y + u, B, v);
	free(A);
	free(B);
}

void decrypt_FF3(unsigned char* K, unsigned char* X, int radix, int n, unsigned char* T, unsigned char *Y) {
	unsigned char* A;
	unsigned char* B;
	int u = ceil((double)n / 2.0) / 1;
	// 	printf("%d\n", u);
	int v = n - u;
	A = malloc(u * sizeof(unsigned char));
	B = malloc(v * sizeof(unsigned char));
	str_to_bytes(A, X, u);
	str_to_bytes(B, X + u, v);
	int half_t_len = FF3_T_LEN / 2;
	unsigned char T_L[half_t_len];
	memcpy(T_L, T, half_t_len);
	unsigned char T_R[half_t_len];
	memcpy(T_R, T + half_t_len, half_t_len);
	unsigned char W[half_t_len];
	int m;
	int i;
	for (i = 7; i >= 0; i--) {
		if (i % 2 == 0) {
			m = u;
			memcpy(W, T_R, half_t_len);
		}
		else {
			m = v;
			memcpy(W, T_L, half_t_len);
		}
		// 		print_bytes(A, n-m, "A");
		// 		print_bytes(B, m, "B");
		unsigned char _i[half_t_len];
		int_to_bytes(_i, i, 4);
		unsigned char P[16];
		unsigned char W_XOR_i[half_t_len];
		XOR_bytes(W_XOR_i, W, _i, half_t_len);
		memcpy(P, W_XOR_i, half_t_len);
		unsigned char revA[n - m];
		reverse_bytes(revA, A, n - m);
		unsigned char num_str[12];
		uint64_t revA64 = str_to_64(revA, n - m, radix);
		int64_to_bytes(num_str, revA64, 12);
		memcpy(P + 4, num_str, 12);
		unsigned char revP[16];
		reverse_bytes(revP, P, 16);
		unsigned char revK[16];
		reverse_bytes(revK, K, 16);
		unsigned char revS[16];
		int ciphertext_len = encrypt_ECB(revP, 16, revK, revS);
		if (ciphertext_len != 16) {
			fprintf(stderr, "Encryption failed.\n");
			exit(0);
		}
		unsigned char S[16];
		reverse_bytes(S, revS, 16);
		int radix_m = (int)pow(radix, m) / 1;
		unsigned char revB[m];
		reverse_bytes(revB, B, m);
		// 		print_bytes(revB, m, "revB");
		uint64_t revB64 = str_to_64(revB, m, radix);
		//printf("revB64: %llu\n", revB64);
		uint64_t ymod = get_ymod(S, 16, m, radix);
		//printf("ymod: %llu\n", ymod);
		uint64_t revB_mod = revB64 % radix_m;
		//printf("revB_mod: %llu\n", revB_mod);
		int test = revB_mod - ymod;
		//printf("test: %d\n", test);
		//printf("test mod: %d\n", test % radix_m);
		int c = (revB_mod - ymod);
		c %= radix_m;
		//printf("c: %d\n", c);
		if (c < 0) {
			c += radix_m;
		}
		//  		printf("c: %d\n", c);
		unsigned char revC[m];
		int64_to_str(revC, m, c, radix);
		unsigned char C[m];
		reverse_bytes(C, revC, m);
		free(B);
		B = malloc((n - m) * sizeof(unsigned char));
		memcpy(B, A, n - m);
		free(A);
		A = malloc(m * sizeof(unsigned char));
		memcpy(A, C, m);
		//  		printf("\n");
	}
	// 	print_bytes(A, m, "A");
	// 	print_bytes(B, n-m, "B");
	bytes_to_ascii(Y, A, u);
	bytes_to_ascii(Y + u, B, v);
	free(A);
	free(B);
}

void Enc(unsigned char* C, unsigned char* T, int encrypt_X, int radix, int len) {
	K = malloc(16);
	memcpy(K, "1234567890123456", 16); // TODO change to random?
	unsigned char plaintext[len];
	if (encrypt_X) {
		memcpy(plaintext, X, len);
	}
	else {
		memcpy(plaintext, Xp, len);
	}
	encrypt_FF3(K, plaintext, radix, len, T, C);
	free(K);
}

unsigned char A_LHR_first_draft(unsigned char* a, uint64_t q) {
	// 	unsigned char Lp = a >> 4;
	// 	unsigned char R = a & 0x0F;
	// 	unsigned long V[10];
	// 	memset(V, 0x0L, 10*sizeof(long));
	// 	unsigned char T[8];
	// 	memset(T, 0, 8);
	// 	int64_t i;
	// 	for (i=0x0LL; i<q; i++) {
	// 		unsigned char C = Enc(T, 1);  // Encrypt X
	// 		unsigned char Cp = Enc(T, 0); // Encrypt X'
	// 		unsigned char A = C >> 4;
	// 		unsigned char Ap = Cp >> 4;
	// 		unsigned char s = (A - Ap) % 10;
	// 		if (s >=10) {
	// 			s += 10;
	// 		}
	// 		s = (s+Lp) % 10;
	// 		V[s] += 1;
	// 		T[0]++;
	// 		int j = 0;
	// 		while (T[j] == 0 && j < 7) {
	// 			j++;
	// 			T[j]++;
	// 		}
	// 	}
	// 	unsigned char L = 0;
	// 	int j;
	// 	for (j=1; j < 10; j++) {
	// 		if (V[j] > V[L]) {
	// 			L = j;
	// 		}
	// 	}
	// 	unsigned char guess = R;
	// 	L = L << 4;
	// 	guess = guess | L;
	return 1;
}

void A_LHR(unsigned char* a, uint64_t q, int radix, int len, unsigned char* guess) {
	Xp = malloc(len);
	memcpy(Xp, a, len);
	int left_len = ceil((double)len / 2.0) / 1;
	unsigned char Lp[left_len];
	memcpy(Lp, Xp, left_len);
	int M = (int)pow(radix, left_len);
	uint64_t V[M];
	memset(V, 0, M * sizeof(uint64_t));
	unsigned char T[8];
	memset(T, 0, 8);
	uint64_t i;
	for (i = 0x0LL; i<q; i++) {
		unsigned char C[len];
		Enc(C, T, 1, radix, len); // Encrypt X
		unsigned char Cp[len];
		Enc(Cp, T, 0, radix, len); // Encrypt X'
		unsigned char A[left_len];
		memcpy(A, C, left_len);
		unsigned char Ap[left_len];
		memcpy(Ap, Cp, left_len);
		unsigned char A_nonascii[left_len];
		str_to_bytes(A_nonascii, A, left_len);
		uint64_t A_num = str_to_64(A_nonascii, left_len, radix);
		unsigned char Ap_nonascii[left_len];
		str_to_bytes(Ap_nonascii, Ap, left_len);
		uint64_t Ap_num = str_to_64(Ap_nonascii, left_len, radix);
		Ap_num %= M;
		A_num %= M;
		int64_t A_diff = A_num - Ap_num;
		A_diff %= M;
		if (A_diff < 0) {
			A_diff += M;
		}
		unsigned char Lp_nonascii[left_len];
		str_to_bytes(Lp_nonascii, Lp, left_len);
		int64_t Lp_num = str_to_64(Lp_nonascii, left_len, radix);
		int64_t s = A_diff + Lp_num;
		s %= M;
		V[s]++;
		T[0]++;
		int j = 0;
		while (T[j] == 0 && j < 7) {
			j++;
			T[j]++;
		}
	}
	uint64_t L = 0x0LL;
	uint64_t j;
	for (j = 0x1LL; j < M; j++) {
		if (V[j] > V[L]) {
			L = j;
		}
	}
	unsigned char L_str[left_len];
	int64_to_str(L_str, left_len, L, radix);
	unsigned char L_ascii[left_len];
	bytes_to_ascii(L_ascii, L_str, left_len);
	memcpy(guess, L_ascii, left_len);
	memcpy(guess + left_len, Xp + left_len, len - left_len);
	uint64_t k;
	for (k = 0x0LL; k<M; k++) {
		printf("%llu: %llu\n", k, V[k]);
	}
}

int G_mr(uint64_t q, int radix, int len) {
	X = malloc(len);
	memcpy(X, "010101001", len);
	unsigned char a[len];
	memcpy(a, "111001001", len);  // X' with same right half as X
	unsigned char A_guess[len];
	A_LHR(a, q, radix, len, A_guess);
	print_bytes(A_guess, len, "A's guess");
	int wrong = memcmp(A_guess, X, len);
	free(X);
	return !wrong;
}

int check_G_mr(uint64_t q, int radix, int len, unsigned char* M, unsigned char* a) {
	X = malloc(len);
	memcpy(X, M, len);
	unsigned char A_guess[len];
	A_LHR(a, q, radix, len, A_guess);
	print_bytes(A_guess, len, "A's guess");
	int wrong = memcmp(A_guess, X, len);
	free(X);
	return !wrong;
}






