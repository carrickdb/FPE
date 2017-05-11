#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <string.h>
#include <math.h>
#include "enc.h"

unsigned char X;
unsigned char Xp;
unsigned char* K;

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
  if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

  /* Initialise the decryption operation. IMPORTANT - ensure you use a key
   * and IV size appropriate for your cipher
   * In this example we are using 256 bit AES (i.e. a 256 bit key). The
   * IV size for *most* modes is the same as the block size. For AES this
   * is 128 bits */
  if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
    handleErrors();

  /* Provide the message to be decrypted, and obtain the plaintext output.
   * EVP_DecryptUpdate can be called multiple times if necessary
   */
  if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
    handleErrors();
  plaintext_len = len;

  /* Finalise the decryption. Further plaintext bytes may be written at
   * this stage.
   */
  if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) handleErrors();
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
  if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

  /* Initialise the encryption operation. IMPORTANT - ensure you use a key
   * and IV size appropriate for your cipher
   * In this example we are using 256 bit AES (i.e. a 256 bit key). The
   * IV size for *most* modes is the same as the block size. For AES this
   * is 128 bits */
  if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
    handleErrors();

  /* Provide the message to be encrypted, and obtain the encrypted output.
   * EVP_EncryptUpdate can be called multiple times if necessary
   */
  if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
    handleErrors();
  ciphertext_len = len;

  /* Finalise the encryption. Further ciphertext bytes may be written at
   * this stage.
   */
  if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) handleErrors();
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
	if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();
	
  	if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, key, NULL))
    	handleErrors();

  	/* Provide the message to be encrypted, and obtain the encrypted output. */
  	if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
  	  handleErrors();
  	ciphertext_len = len;

  	/* Clean up */
  	EVP_CIPHER_CTX_free(ctx);

  	return ciphertext_len;
}

void print_bytes(unsigned char *mem, int size) {
  int i;
  for (i = 0; i < size; i++) {
    printf("%02x ", mem[i]);
    if ((i%16==0) && i)
      printf("\n");
  }
  printf("\n");
}

void int_to_bytes(unsigned char* buf, int num, int len) {
	int i;
	for (i=0; i < len; i++) { 
		buf[i] = (num >> (8*(len - i - 1))) & 0xFF;
	}
}

void long_to_bytes(unsigned char* buf, long num, int len) {
	int i;
	for (i=0; i < len; i++) { 
		buf[i] = (num >> (8*(len - i - 1))) & 0xFF;
	}
}

/* This is an implementation of NIST FPE standard FF1. */
void encrypt_FF1(char* m, int radix, int m_len, unsigned char* tweak, int tweak_len) {
	// check message and tweak length? numerical string formation?
	char c[m_len];
	int u = m_len/2;
	int v = m_len - u;
	char L[u];
	memcpy(L, m, u);
	char R[v];
	memcpy(R, m+u, v);
	double b = log(radix) / log(2);
	b = ceil(v*b);
	b = ceil(b/8.0);
	int b_int = ceil(b/4)/1; // cieling(ceiling(8*(log base 2 of 10))/8) = 4
	int d = b_int*4 + 4;
	fprintf(stderr, "%d\n", b_int);
	unsigned char P[] = {1, 2, 1, 0, 0, 0, 10, u % 256, 0, 0, 0, 0, 0, 0, 0, 0};
	int_to_bytes(P+3, 0xFFFFFF, 3);
	int_to_bytes(P+8, m_len, 4);
	int_to_bytes(P+12, tweak_len, 4);
	int rem = (-tweak_len - b_int - 1) % 16; 
	if (rem < 0) {
		rem += 16;
	}
	int Q_len = tweak_len + rem + 1 + b_int;
	fprintf(stderr, "%d\n", Q_len);
	int i;
	for (i = 0; i < 10; i++) {
		unsigned char Q[Q_len];
		memset(Q, 0, sizeof(Q));
		memcpy(Q, tweak, tweak_len);
		int_to_bytes(Q+tweak_len+rem, i, 1);
		long R_long = atol(R);  // May need to make this longer
		long_to_bytes(Q+tweak_len+rem+1, R_long, 8);
		//print_hex_memory(Q, sizeof(Q));
	}
}

void XOR_bytes(unsigned char* A_XOR_B, unsigned char *A, unsigned char *B, int len) {
	int i;
	for (i = 0; i < len; i++) {
		A_XOR_B[i] = A[i] ^ B[i];
	}
}

void reverse_bytestring(unsigned char* rev_bytestr, unsigned char* bytestr, int len) {
	int i;
	for (i = 0; i < len/2; i++) {
		rev_bytestr[i] = bytestr[len-i-1];
		rev_bytestr[len-i-1] = bytestr[i];
	}
	if (len%2!=0) {
		rev_bytestr[len/2+1] = bytestr[len/2+1];
	}
}

void encrypt_FF3(unsigned char* K, unsigned char* X, int radix, int n, unsigned char* T) {
	int u = ceil(n/2)/1;
	int v = n - u;
	unsigned char A[u];
	memcpy(A, X, u);
	unsigned char B[v];
	memcpy(B, X+u, v);
	int half_t_len = FF3_T_LEN/2;
	unsigned char T_L[half_t_len];
	memcpy(T_L, T, half_t_len);
	unsigned char T_R[half_t_len];
	memcpy(T_R, T+half_t_len, half_t_len);
	unsigned char W[half_t_len];
	int i;
	for (i = 0; i < 8; i++) {
		int m;
		if (i%2 == 0) {
			m = u;
			memcpy(W, T_R, half_t_len);
		} else {
			m = v;
			memcpy(W, T_L, half_t_len);
		}
		unsigned char _i[half_t_len];
		unsigned char P[half_t_len];
		unsigned char W_XOR_i[half_t_len];
		XOR_bytes(W_XOR_i, W, _i, half_t_len);
		memcpy(P, W_XOR_i, half_t_len);
		unsigned char A_rev[u];
		//print_hex_memory(A, n);
		reverse_bytestring(A_rev, A, n);
		//print_hex_memory(A_rev, n);
	}
}


/* This is an implementation of FF3 encryption for 2 decimal numerals. */
void encrypt_FF3_2_dec(unsigned char* K, unsigned char* X, unsigned char* T, unsigned char * Y) {
	// K = key; X = message; T = tweak (64 bits long)
	unsigned char A = X[0];
	unsigned char B = X[1];
	int half_t_len = FF3_T_LEN/2;
	unsigned char T_L[half_t_len];
	memcpy(T_L, T, half_t_len);
	unsigned char T_R[half_t_len];
	memcpy(T_R, T+half_t_len, half_t_len);
	unsigned char W[half_t_len];
	int i;
	for (i = 0; i < 8; i++) {
		if (i%2 == 0) {
			memcpy(W, T_R, half_t_len);
		} else {
			memcpy(W, T_L, half_t_len);
		}
		unsigned char _i[4];
		int_to_bytes(_i, i, 4);		
		unsigned char P[16];
		unsigned char W_XOR_i[half_t_len];
		XOR_bytes(W_XOR_i, W, _i, half_t_len);
		memcpy(P, W_XOR_i, half_t_len);
		unsigned char B_str[12];
		memset(B_str, 0, 12);
		B_str[11] = B - '0';
		memcpy(P+4, B_str, 12);
		unsigned char P_rev[16];
		reverse_bytestring(P_rev, P, 16);
		unsigned char K_rev[16];
		reverse_bytestring(K_rev, K, 16);
		unsigned char S_rev[16];
//		print_hex_memory(P_rev, 16);
		int ciphertext_len = encrypt_ECB(P_rev, 16, K_rev, S_rev);
//		print_hex_memory(S_rev, 16);
		unsigned char S[16];
		reverse_bytestring(S, S_rev, 16);
		unsigned char y_mod = S[15] % 10;
		//fprintf(stderr, "y_mod: %x\n", y_mod);
		unsigned char A_num_mod = (A - '0') % 10;
		//fprintf(stderr, "A_num_mod: %x\n", A_num_mod);
		unsigned char c = (A_num_mod + y_mod) % 10;
		//fprintf(stderr, "c: %x\n", c);
		A = B;
		unsigned char C = c + '0';
		B = C; 
	}
  	EVP_cleanup();
	ERR_free_strings();
	Y[0] = A;
	Y[1] = B;
}


/* An implementation of FF3 decryption for 2 decimal numerals. */
void decrypt_FF3_2_dec(unsigned char* K, unsigned char* X, unsigned char* T, unsigned char * Y) {
	// K = key; X = message; T = tweak (64 bits long); Y = buffer for decrypted message
	unsigned char A = X[0];
	unsigned char B = X[1];
	int half_t_len = FF3_T_LEN/2;
	unsigned char T_L[half_t_len];
	memcpy(T_L, T, half_t_len);
	unsigned char T_R[half_t_len];
	memcpy(T_R, T+half_t_len, half_t_len);
	unsigned char W[half_t_len];
	int i;
	for (i = 7; i >= 0; i--) {
		if (i%2 == 0) {
			memcpy(W, T_R, half_t_len);
		} else {
			memcpy(W, T_L, half_t_len);
		}
		unsigned char _i[4];
		int_to_bytes(_i, i, 4);		
		unsigned char P[16];
		unsigned char W_XOR_i[half_t_len];
		XOR_bytes(W_XOR_i, W, _i, half_t_len);
		memcpy(P, W_XOR_i, half_t_len);
		unsigned char A_str[12];
		memset(A_str, 0, 12);
		A_str[11] = A - '0';
		memcpy(P+4, A_str, 12);
		unsigned char P_rev[16];
		reverse_bytestring(P_rev, P, 16);
		unsigned char K_rev[16];
		reverse_bytestring(K_rev, K, 16);
		unsigned char S_rev[16];
//		print_hex_memory(P_rev, 16);
		int ciphertext_len = encrypt_ECB(P_rev, 16, K_rev, S_rev);
//		print_hex_memory(S_rev, 16);
		unsigned char S[16];
		reverse_bytestring(S, S_rev, 16);
		unsigned char y_mod = S[15] % 10;
		unsigned char B_num_mod = (B - '0') % 10;
		int c = (B_num_mod - y_mod) % 10;
		if (c < 0) {
			c += 10;
		}
		B = A;
		unsigned char C = c + '0';
		A = C;
	}
  	EVP_cleanup();
	ERR_free_strings();
	Y[0] = A;
	Y[1] = B;
}

/* This is an implementation of FF3 encryption for one byte. */
unsigned char encrypt_FF3_8_bits(unsigned char* K, unsigned char X, unsigned char* T) {
	// K = key; X = message; T = tweak (64 bits long)
	int half_t_len = FF3_T_LEN/2;
	unsigned char T_L[half_t_len];
	memcpy(T_L, T, half_t_len);
	unsigned char T_R[half_t_len];
	memcpy(T_R, T+half_t_len, half_t_len);
	unsigned char W[half_t_len];
	unsigned char A = X >> 4;
	unsigned char B = X & 0x0F;
	int i;
	for (i = 0; i < 8; i++) {
		if (i%2 == 0) {
			memcpy(W, T_R, half_t_len);
		} else {
			memcpy(W, T_L, half_t_len);
		}
		unsigned char _i[4];
		int_to_bytes(_i, i, 4);		
		unsigned char P[16];
		unsigned char W_XOR_i[half_t_len];
		XOR_bytes(W_XOR_i, W, _i, half_t_len);
		memcpy(P, W_XOR_i, half_t_len);
		unsigned char B_str[12];
		memset(B_str, 0, 12);
		B_str[11] = B;
		memcpy(P+4, B_str, 12);
		unsigned char P_rev[16];
		reverse_bytestring(P_rev, P, 16);
		unsigned char K_rev[16];
		reverse_bytestring(K_rev, K, 16);
		unsigned char S_rev[16];
//		print_hex_memory(P_rev, 16);
		int ciphertext_len = encrypt_ECB(P_rev, 16, K_rev, S_rev);
//		print_hex_memory(S_rev, 16);
		unsigned char S[16];
		reverse_bytestring(S, S_rev, 16);
		unsigned char y_mod = S[15] % 10;
		//fprintf(stderr, "y_mod: %x\n", y_mod);
		unsigned char A_num_mod = A % 10;
		//fprintf(stderr, "A_num_mod: %x\n", A_num_mod);
		unsigned char c = (A_num_mod + y_mod) % 10;
		A = B;
		B = c; 
	}
	unsigned char Y = B;
//	fprintf(stderr, "A: %02x\n", A);
//	fprintf(stderr, "B: %02x\n", B);
	Y = Y | (A << 4);
  	EVP_cleanup();
	ERR_free_strings();
	return Y;
}

/* An implementation of FF3 decryption for 8 bits. */
unsigned char decrypt_FF3_8_bits(unsigned char* K, unsigned char X, unsigned char* T) {
	// K = key; X = message; T = tweak (64 bits long); Y = buffer for decrypted message
	unsigned char A = X >> 4;
	unsigned char B = X & 0x0F;
	int half_t_len = FF3_T_LEN/2;
	unsigned char T_L[half_t_len];
	memcpy(T_L, T, half_t_len);
	unsigned char T_R[half_t_len];
	memcpy(T_R, T+half_t_len, half_t_len);
	unsigned char W[half_t_len];
	int i;
	for (i = 7; i >= 0; i--) {
		if (i%2 == 0) {
			memcpy(W, T_R, half_t_len);
		} else {
			memcpy(W, T_L, half_t_len);
		}
		unsigned char _i[4];
		int_to_bytes(_i, i, 4);		
		unsigned char P[16];
		unsigned char W_XOR_i[half_t_len];
		XOR_bytes(W_XOR_i, W, _i, half_t_len);
		memcpy(P, W_XOR_i, half_t_len);
		unsigned char A_str[12];
		memset(A_str, 0, 12);
		A_str[11] = A;
		memcpy(P+4, A_str, 12);
		unsigned char P_rev[16];
		reverse_bytestring(P_rev, P, 16);
		unsigned char K_rev[16];
		reverse_bytestring(K_rev, K, 16);
		unsigned char S_rev[16];
//		print_hex_memory(P_rev, 16);
		int ciphertext_len = encrypt_ECB(P_rev, 16, K_rev, S_rev);
//		print_hex_memory(S_rev, 16);
		unsigned char S[16];
		reverse_bytestring(S, S_rev, 16);
		unsigned char y_mod = S[15] % 10;
		unsigned char B_num_mod = B % 10;
		int c = (B_num_mod - y_mod) % 10;
		if (c < 0) {
			c += 10;
		}
		B = A;
		A = c;
	}
	unsigned char Y = B;
//	fprintf(stderr, "A: %02x\n", A);
//	fprintf(stderr, "B: %02x\n", B);
	Y = Y | (A << 4);
  	EVP_cleanup();
	ERR_free_strings();
	return Y;
}


unsigned char Enc(unsigned char* T, int encrypt_X) {
	unsigned char curr_msg = 0;
	if (!encrypt_X) {
		//printf("I am encrypting X'=");
		curr_msg = Xp;
	} else {
		//printf("I am encrypting X=");
		curr_msg = X;
	}
	//printf("%02x with tweak ", curr_msg);
	//print_bytes(T, 8);
	return encrypt_FF3_8_bits(K, curr_msg, T);
}


void p(unsigned char num, char* name) {
	fprintf(stderr, "%s: %02x\n", name, num);
}


unsigned char A_LHR(unsigned char a, int64_t q) {
	// Change start of tweaks? 
	//p(a, "a");
	unsigned char Lp = a >> 4;
	unsigned char R = a & 0x0F;
	//p(Lp, "Lp");
	//p(R, "R");
	unsigned long V[10];
	memset(V, 0x0L, 10*sizeof(long));
// 	fprintf(stderr, "V: ");
// 	int k;
// 	for (k=0; k<10; k++) {
// 		fprintf(stderr, "%li", V[k]);
// 	}
// 	fprintf(stderr, "\n");
	unsigned char T[8];
	memset(T, 0, 8);
	//print_bytes(T, 8);
	int64_t i;
	for (i=0x0LL; i<q; i++) {
		unsigned char C = Enc(T, 1);  // Encrypt X
		unsigned char Cp = Enc(T, 0); // Encrypt X'
		unsigned char A = C >> 4;
		unsigned char Ap = Cp >> 4;
		
		unsigned char s = (A - Ap) % 10;
//		p(s, "s");
		if (s >=10) {
			s += 10;
			//p(s, "new s");
		}
		s = (s+Lp) % 10;
		V[s] += 1;
		T[0]++;
		int j = 0;
		while (T[j] == 0 && j < 7) {
			j++;
			T[j]++;
		}
		//fprintf(stderr, "new tweak: ");
		//print_hex_memory(T, 8);
	}
	unsigned char L = 0;
	fprintf(stderr, "Final V: %li", V[0]);
	int j;
	for (j=1; j < 10; j++) {
		fprintf(stderr, " %li", V[j]);
		if (V[j] > V[L]) {
			L = j;
		}
	}
	fprintf(stderr, "\n");
	unsigned char guess = R;
	L = L << 4;
	guess = guess | L;
	return guess; 
}


int G_mr(int64_t q) {
	K = malloc(16*sizeof(char));
	memcpy(K, "1234567890123456", 16); // TODO change to random?
	X = 0x84; // Target message X
	p(X, "X");
	unsigned char a = 0x24;  // X' with equal right half
	Xp = a;
	p(Xp, "X'");
	unsigned char A_guess = A_LHR(a, q);
	fprintf(stderr, "A_LHR's guess: %02x\n", A_guess);
	free(K);
	return (A_guess == X);
}








