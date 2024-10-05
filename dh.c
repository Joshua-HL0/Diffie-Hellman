#include "dh.h"

void mod_pow(uint8_t *base, uint8_t *pow, uint8_t *mod, uint8_t *result) {
     
    // trying to do everything with regular int arrays caused too many issues, openssl it is!
    BIGNUM *b_base = BN_bin2bn(base, KEY_SIZE / 8, NULL);
    BIGNUM *b_pow = BN_bin2bn(pow, KEY_SIZE / 8, NULL);
    BIGNUM *b_mod = BN_bin2bn(mod, KEY_SIZE / 8, NULL);
    BIGNUM *b_result = BN_new();
    BN_CTX *ctx = BN_CTX_new();

    BN_mod_exp(b_result, b_base, b_pow, b_mod, ctx);

    // Convert result back to uint8_t array
    BN_bn2bin(b_result, result);

    BN_free(b_base);
    BN_free(b_pow);
    BN_free(b_mod);
    BN_free(b_result);
    BN_CTX_free(ctx);
    
}

void generate_keys(uint8_t *private_key, uint8_t *public_key, uint8_t *prime, uint8_t *generator){
    
    int ur = open("/dev/urandom", O_RDONLY);
    if (ur < 0){
        perror("Couldn't open urandom");
        exit(EXIT_FAILURE);
    }

    ssize_t result = read (ur, private_key, KEY_SIZE / 8);
    if (result < 0){
        perror("Failed to read urandom");
        close(ur);
        exit(EXIT_FAILURE);
    }

    close(ur);

    /*for (int i = 0; i < KEY_SIZE / 8; i++) {
        private_key[i] = rand() % 256; // using rand() isn't secure, use whichever source of randomness you prefer.
    }*/

    // Calculate public key: public_key = base^private_key mod modulus
    mod_pow(generator, private_key, prime, public_key);
}

void calc_shared_secret(uint8_t *private_key, uint8_t *foreign_public_key, uint8_t *prime, uint8_t *shared_secret) { 
    // shared_secret = other_public_key^private_key mod modulus
    mod_pow(foreign_public_key, private_key, prime, shared_secret);
}
