#include "dh.h"

int main() {
    
    uint8_t generator[] = {2};

    uint8_t prime[256] = {                            // Standard 2048 bit dh prime
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 
    0xAD, 0xF8, 0x54, 0x58, 0xA2, 0xBB, 0x4A, 0x9A, 
    0xAF, 0xDC, 0x56, 0x20, 0x27, 0x3D, 0x3C, 0xF1, 
    0xD8, 0xB9, 0xC5, 0x83, 0xCE, 0x2D, 0x36, 0x95, 
    0xA9, 0xE1, 0x36, 0x41, 0x14, 0x64, 0x33, 0xFB, 
    0xCC, 0x93, 0x9D, 0xCE, 0x24, 0x9B, 0x3E, 0xF9, 
    0x7D, 0x2F, 0xE3, 0x63, 0x63, 0x0C, 0x6D, 0x80, 
    0x16, 0xAD, 0x8A, 0x8E, 0xE1, 0xAF, 0xD5, 0x4E, 
    0x15, 0xD3, 0xF6, 0xA9, 0x3A, 0xB3, 0x3D, 0xA7, 
    0x35, 0x5B, 0x62, 0x85, 0x0E, 0x94, 0xDB, 0x43, 
    0x8A, 0xAB, 0xF1, 0x3C, 0x6D, 0x9A, 0x51, 0xB6, 
    0x3F, 0x42, 0x9F, 0xED, 0x5B, 0xBE, 0x85, 0xD6, 
    0xF6, 0xF8, 0x8A, 0x7D, 0xE4, 0x57, 0x75, 0xF4, 
    0x6F, 0x44, 0xC0, 0x6E, 0x0E, 0x68, 0xB7, 0x7E, 
    0x2A, 0x9B, 0x8D, 0xBF, 0x2F, 0xCA, 0xF9, 0x19, 
    0xEB, 0xAA, 0x9F, 0x45, 0x6C, 0x52, 0xF5, 0xFC, 
    0xB8, 0x2B, 0x88, 0x9D, 0x6E, 0xFD, 0xD7, 0xE8, 
    0xF9, 0xDF, 0x79, 0xB1, 0x86, 0x7B, 0x9A, 0x9C, 
    0xFD, 0xB6, 0x87, 0x32, 0x1A, 0x8A, 0x55, 0x17, 
    0x51, 0x5B, 0xE7, 0xED, 0x1F, 0x61, 0x29, 0x70, 
    0xC0, 0x5C, 0x24, 0x71, 0x96, 0xA6, 0xA9, 0x93, 
    0x2E, 0x99, 0xB6, 0x4E, 0x6F, 0x44, 0xEE, 0x62, 
    0x92, 0x53, 0x6B, 0x14, 0x2E, 0x00, 0x10, 0xAA, 
    0x20, 0x21, 0xB0, 0x8B
    };

    uint8_t private_key_a[KEY_SIZE / 8];
    uint8_t public_key_a[KEY_SIZE / 8];
    uint8_t private_key_b[KEY_SIZE / 8];
    uint8_t public_key_b[KEY_SIZE / 8];
    uint8_t shared_secret_a[KEY_SIZE / 8];
    uint8_t shared_secret_b[KEY_SIZE / 8];

    // Generate keys for both parties
    generate_keys(private_key_a, public_key_a, prime, generator);
    generate_keys(private_key_b, public_key_b, prime, generator);

    // Compute shared secrets
    calc_shared_secret(private_key_a, public_key_b, prime, shared_secret_a);
    calc_shared_secret(private_key_b, public_key_a, prime, shared_secret_b);

    printf("Public Key A: ");
    for (int i = 0; i < KEY_SIZE / 8; i++) {
        printf("%02x ", public_key_a[i]);
    }
    printf("\n");

    printf("Public Key B: ");
    for (int i = 0; i < KEY_SIZE / 8; i++) {
        printf("%02x ", public_key_b[i]);
    }
    printf("\n");

    printf("Shared Secret A: ");
    for (int i = 0; i < KEY_SIZE / 8; i++) {
        printf("%02x ", shared_secret_a[i]);
    }
    printf("\n");

    printf("Shared Secret B: ");
    for (int i = 0; i < KEY_SIZE / 8; i++) {
        printf("%02x ", shared_secret_b[i]);
    }
    printf("\n");

    return 0;
}
