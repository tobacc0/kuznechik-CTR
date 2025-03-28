#include "kuz_ctr_calc.h"


void print_debug_block(const uint8_t *out_block) {
    for (int i = 0; i < BLOCK_SIZE; i++)
        printf("%02x", out_block[i]);
    printf("\n");
}

void print_debug_file(FILE* f) {
	char ch;
 	rewind(f);
 	while ((ch = fgetc(f)) != EOF) {
        printf("%c", ch);
    }
} 

uint8_t* get_hex(FILE *f, const uint8_t size, const int skip) {
	int rv;
	uint8_t* num = malloc(size);
	fseek(f, 2 * skip * BLOCK_SIZE, SEEK_SET);
	int i = 0;
	while (i < size) {
		rv = fscanf(f, "%02x", &num[i]);
		if (rv != 1) {
			i++;
			continue;
		} 
		i++;
	}
	return num;
}

void print_hex(FILE *f, uint8_t* num,  const uint8_t size) {
	int rv;
	int i = 0;
	fseek(f, 0, SEEK_END);
	while (i < size) {
		fprintf(f, "%02x", num[i]);
		i++;
	}
}

static void kuz_xor(const uint8_t *a, const uint8_t *b, uint8_t *c) {
    for (int i = 0; i < BLOCK_SIZE; i++) c[i] = a[i] ^ b[i];
}

static uint8_t GF_mul(uint8_t a, uint8_t b) {
    uint8_t res = 0;
    uint8_t hi_bit;
    for (int i=0; i < 8; i++) {
        if (b & 1) 
            res ^= a;
        hi_bit = a & 0x80;
        a <<= 1;
        if (hi_bit)
            a ^= 0xc3;
        b >>= 1;
    }
    return res;
}

static void S(const uint8_t *in_data, uint8_t *out_data) {
    for (int i = 0; i < BLOCK_SIZE; i++) {
        out_data[i] = Pi[in_data[i]];
    }
}

static void reverse_S(const uint8_t *in_data, uint8_t *out_data) {
    for (int i = 0; i < BLOCK_SIZE; i++) {
        out_data[i] = reverse_Pi[in_data[i]];
    }
}

static void linear_transformation(uint8_t *state) {
    block internal;
    uint8_t a_15 = 0;
    for (int i = 15; i >= 0; i--) {
    	if (i - 1 >= 0)
       		internal[i-1] = state[i];
        a_15 ^= GF_mul(state[i], L_vec[i]);
    }
    internal[15] = a_15;
    memcpy(state, internal, BLOCK_SIZE);
}

static void reverse_linear_transformation(uint8_t *state) {
    block internal;
    uint8_t a_0 = 0;
    for (int i = 0; i < 16; i++) {
        internal[i] = state[i - 1];
        a_0 ^= GF_mul(state[i], L_vec[i]);
    }
    internal[0] = a_0;
    memcpy(state, internal, BLOCK_SIZE);
}


static void kuz_L(const uint8_t *in_data, uint8_t *out_data) {
    block internal;
    memcpy(internal, in_data, BLOCK_SIZE);
    for (int i=0; i < 16; i++) linear_transformation(internal);
    memcpy(out_data, internal, BLOCK_SIZE); 
}

static void reverse_L(const uint8_t *in_data, uint8_t *out_data) {
    block internal;
    memcpy(internal, in_data, BLOCK_SIZE);
    for (int i; i < 16; i++) reverse_linear_transformation(internal);
    memcpy(out_data, internal, BLOCK_SIZE); 
}

/*
getting round consts. for each iteration we have
iteration number we use to get a const using
L-transformation on that number.
*/
static void get_C() {
    block iterations[32];
    int i;
    for (i=0; i < 32; i++) {
        memset(iterations[i], 0, BLOCK_SIZE);
        iterations[i][0] = i+1;
    }

    for (i=0; i< 32; i++) {
        kuz_L(iterations[i], round_Cs[i]);
    }
}

/*
an iteration of Feistel network to generate round keys
from master-key. 
*/
static void iterate_Feistel(const uint8_t *in_keypair_1, const uint8_t *in_keypair_2,
                            uint8_t *out_keypair_1, uint8_t *out_keypair_2,
                            uint8_t *round_C) {
    block internal;
    memcpy(out_keypair_2, in_keypair_1, BLOCK_SIZE);
    kuz_xor(in_keypair_1, round_C, internal);
    S(internal, internal);
    kuz_L(internal, internal);
    kuz_xor(internal, in_keypair_2, out_keypair_1);
}

void kuz_get_round_keys(const uint8_t *key) {
    uint8_t keypair_1[KEY_SIZE/2];
    uint8_t keypair_2[KEY_SIZE/2];
    
    uint8_t prev_key_1[KEY_SIZE/2];
    uint8_t prev_key_2[KEY_SIZE/2];

    uint8_t curr_key_1[KEY_SIZE/2];
    uint8_t curr_key_2[KEY_SIZE/2];
    memcpy(keypair_1, key + KEY_SIZE/2, KEY_SIZE/2);
    memcpy(keypair_2, key, KEY_SIZE/2);
    get_C();

    memcpy(round_keys[0], keypair_1, KEY_SIZE/2);
    memcpy(round_keys[1], keypair_2, KEY_SIZE/2);

	memcpy(prev_key_1, keypair_1, KEY_SIZE/2);
    memcpy(prev_key_2, keypair_2, KEY_SIZE/2);
    for (int i = 0; i < 4; i++) {
        iterate_Feistel(prev_key_1, prev_key_2, curr_key_1, curr_key_2, round_Cs[8 * i + 0]);
        iterate_Feistel(curr_key_1, curr_key_2, prev_key_1, prev_key_2, round_Cs[8 * i + 1]);
        iterate_Feistel(prev_key_1, prev_key_2, curr_key_1, curr_key_2, round_Cs[8 * i + 2]);
        iterate_Feistel(curr_key_1, curr_key_2, prev_key_1, prev_key_2, round_Cs[8 * i + 3]);
        iterate_Feistel(prev_key_1, prev_key_2, curr_key_1, curr_key_2, round_Cs[8 * i + 4]);
        iterate_Feistel(curr_key_1, curr_key_2, prev_key_1, prev_key_2, round_Cs[8 * i + 5]);
        iterate_Feistel(prev_key_1, prev_key_2, curr_key_1, curr_key_2, round_Cs[8 * i + 6]);
        iterate_Feistel(curr_key_1, curr_key_2, prev_key_1, prev_key_2, round_Cs[8 * i + 7]);
        memcpy(round_keys[2 * i + 2], prev_key_1, KEY_SIZE/2);
        memcpy(round_keys[2 * i + 3], prev_key_2, KEY_SIZE/2);
    }
}

void kuz_encrypt(const uint8_t *text, uint8_t *out_text) {
    memcpy(out_text, text, BLOCK_SIZE);
    for (int i=0; i < 9; i++) {
        kuz_xor(round_keys[i], out_text, out_text);
        S(out_text, out_text);
        kuz_L(out_text, out_text);
    }
    kuz_xor(out_text, round_keys[9], out_text);
}

static void increase_ctr(uint8_t *ctr) {
    unsigned int internal = 0;
    uint8_t bit[BLOCK_SIZE];
    memset(bit, 0x00, BLOCK_SIZE);
    bit[BLOCK_SIZE - 1] = 0x01;
    for (int i = BLOCK_SIZE - 1; i >= 0; i--) {
        internal = ctr[i] + bit[i] + (internal >> 8);
        ctr[i] = internal & 0xff;
    }
}

void clear_ctr(uint8_t *ctr) {
	memset(ctr, 0x00, BLOCK_SIZE);
}

void destroy_key() {
    for (int i = 0; i < 10; i++) memset(round_keys[i], 0x00, BLOCK_SIZE);
}


void CTR_encrypt(uint8_t *ctr, const uint8_t *text, uint8_t *out_text, 
                const uint8_t *key, uint64_t size) {
	memcpy(out_text, text, size);
    uint64_t num_blocks = size / BLOCK_SIZE;
    printf("\n[Kuznechik CTR]: CTR initiated. Number of blocks: %d", num_blocks);
    uint8_t gamma[BLOCK_SIZE];
    uint8_t internal[BLOCK_SIZE];
	int i;
	

    kuz_get_round_keys(key);
	for (i=0; i < num_blocks; i++) {
	    kuz_encrypt(ctr, gamma);
	    increase_ctr(ctr);
	    memcpy(internal, text + i*BLOCK_SIZE, BLOCK_SIZE);
	    kuz_xor(internal, gamma, internal);
	    memcpy(out_text + i*BLOCK_SIZE, internal, BLOCK_SIZE);
	    size -= BLOCK_SIZE;
	}

    if (size > 0) {
        kuz_encrypt(ctr, gamma);
        increase_ctr(ctr);
        memcpy(internal, text + i*BLOCK_SIZE, size);
        kuz_xor(internal, gamma, internal);
        memcpy(out_text + num_blocks*BLOCK_SIZE, internal, size);
        size = 0;
    }
    destroy_key();
}

void CTR_encrypt_file(FILE *src, FILE *dst, uint8_t *ctr, const uint8_t *key, uint64_t size) {
	uint8_t *in_buf = malloc(BLOCK_SIZE);
	uint8_t *out_buf = malloc(BLOCK_SIZE);
	uint8_t gamma[BLOCK_SIZE];
    int skip = 0;
    
 	while (size) {
 		if (size > BLOCK_SIZE) {
	 		in_buf = get_hex(src, BLOCK_SIZE, skip);
 			CTR_encrypt(ctr, in_buf, out_buf, key, BLOCK_SIZE);
	 		print_hex(dst, out_buf, BLOCK_SIZE);
 			size -= BLOCK_SIZE;
 			skip++;
 		}
	 	else {
	 		in_buf = get_hex(src, size, skip);
	 		CTR_encrypt(ctr, in_buf, in_buf, key, size);
	 		print_hex(dst, in_buf, size);
	 		size = 0;
	 	}
 	}
 	
 	printf("\nInput: ");
 	print_debug_file(src);
 	printf("\nOutput: ");
 	print_debug_file(dst);
 	printf("\n");
}
