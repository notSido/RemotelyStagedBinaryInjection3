#ifndef RC4_H
#define RC4_H

#include <stdio.h>
#include <string.h>

// RC4 Encryption/Decryption function
static void rc4(unsigned char* key, unsigned int keylen, unsigned char* data, unsigned int datalen) {
    unsigned char S[256];
    unsigned char temp;
    int i, j = 0;

    // KSA Phase (Key-Scheduling Algorithm)
    for (i = 0; i < 256; i++)
        S[i] = i;

    for (i = 0; i < 256; i++) {
        j = (j + S[i] + key[i % keylen]) % 256;
        temp = S[i];
        S[i] = S[j];
        S[j] = temp;
    }

    // PRGA Phase (Pseudo-Random Generation Algorithm)
    i = j = 0;
    for (unsigned int n = 0; n < datalen; n++) {
        i = (i + 1) % 256;
        j = (j + S[i]) % 256;

        temp = S[i];
        S[i] = S[j];
        S[j] = temp;

        data[n] ^= S[(S[i] + S[j]) % 256];
    }
}

#endif // RC4_H