#include "src/kuz_ctr_calc.h"
#include "kuz_test.h"


int main(int argc, char *agrv[]) {
	unsigned char ctr[BLOCK_SIZE] =
    {
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
    };
    
    if (sizeof(test_key) / sizeof(test_key[0]) != 32) {
    	printf("Invalid key!\n");
    	return 0;
    }

    FILE *in = fopen("in.txt", "r");
    
    if (in == NULL){
        printf("No input file \n");
        return 0;
    }
    
    FILE *res = fopen("in_enc.txt", "w+");
    FILE *cipher_block = fopen("out.txt", "w+");
    fseek(in, 0L, SEEK_END);
	uint8_t size = ftell(in) / 2;

    printf("===============\n[Kuznechik CTR]: Ecnryption initiated ");
    CTR_encrypt_file(in, res, ctr, test_key, size);
    fclose(res);
    
    res = fopen("in_enc.txt", "r");
    clear_ctr(ctr);
    printf("\n[Kuznechik CTR]: Clearing out the CTR...\nCleared. CTR: ");
    print_debug_block(ctr);
    
    printf("\n===============\n[Kuznechik CTR]: Decryption initiated ");
    CTR_encrypt_file(res, cipher_block, ctr, test_key, size);
    
    fclose(in);
    fclose(res);
    fclose(cipher_block);
    
    return 0;
}

