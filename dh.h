#ifndef DH_H
#define DH_H

#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <stdio.h>
#include <fcntl.h>
#include <openssl/bn.h>

#define KEY_SIZE 256

void mod_pow(uint8_t *base, uint8_t *pow, uint8_t *mod, uint8_t *result);
void generate_keys(uint8_t *private_key, uint8_t *public_key, uint8_t *prime, uint8_t *generator);
void calc_shared_secret(uint8_t *private_key, uint8_t *public_key, uint8_t *prime, uint8_t *shared_key);
void print_key(const char *name, const uint8_t *key);

#endif
