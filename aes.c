#include <stdio.h>
#include <ctype.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#define BUFFSIZE 256
#define KEYSIZE 176
#define HEXBASE 16

// defining N as 4 since NB == NK for 128bit AES-Implementation
// NR is 10 as there are 10 rounds in 128bit AES-Implementation
#define N 4
#define NR 10

// redefine unsigned char for conciseness
typedef unsigned char u_char;

// sbox tables
u_char SBOX_BUFFER[BUFFSIZE];
u_char INV_SBOX_BUFFER[BUFFSIZE];

// round constant word, right shift and inverse right shift lookup tables
u_char RCON[] = { 0x8d,0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36,0x6c,0xd8,0xab,0x4d,0x9a};
u_char RSHIFT[] = { 0, 5, 10, 15, 4, 9, 14, 3, 8, 13, 2, 7, 12, 1, 6, 11 };
u_char RSHIFT_INV[] = { 0, 13, 10,  7,
                        4,  1, 14, 11,
                        8,  5,  2, 15,
                        12,  9,  6,  3 };

// prototypes
void xor_oprn(u_char*, const u_char*, int);
void add_round_key(u_char*, const u_char*, int);
void sub_bytes(u_char*, int);
void inv_sub_bytes(u_char*, int);
void scheduler(u_char*, int);
void expand_key(const u_char*, u_char*);
void shift_rows(u_char*);
void inv_shift_rows(u_char*);
void mix_columns(u_char*);
u_char galois_multiplication(u_char, u_char);
void inv_mix_columns(u_char*);
void encrypt(const u_char*, const u_char*, u_char*);
void decrypt(const u_char*, const u_char*, u_char*);
void extract(u_char*, char*, int);
void printBuffer(u_char*, int);
void aes_processing(char*, char*);

int main(int argc, char *argv[]) {
    if (argc != 3)
        printf("--> Error: This program accepts the plaintext file and a key file as parameters!");
    else{
        printf("--> PlainText Filename: %s\n", argv[1]);
        printf("--> Key Filename:       %s\n\n", argv[2]);
        aes_processing(argv[1], argv[2]);
    }
    return 0;
}

void xor_oprn(u_char *operandA, const u_char *operandB, int numElements) {
    for (int i=0; i<numElements; i++)
        operandA[i] ^= operandB[i];
}

void add_round_key(u_char *currState, const u_char *keySchedule, int currRound){
    xor_oprn(currState, keySchedule + currRound * HEXBASE, HEXBASE);
}

void sub_bytes(u_char * word, int num){
    for(int i=0; i < num; i++)
        word[i] = SBOX_BUFFER[word[i]];
}

void inv_sub_bytes(u_char * word, int num){
    for(int i=0; i < num; i++)
        word[i] = INV_SBOX_BUFFER[word[i]];
}

void scheduler(u_char * word, int rconItrValue){
    // take a word[a0, a1, a2, a3] and perform cyclic permutation for word[a1, a2, a3, a0] (the RotWord Oprn)
    u_char temp;
    temp = word[0];
    word[0] = word[1];
    word[1] = word[2];
    word[2] = word[3];
    word[3] = temp;

    // Take a 4-byte word and apply the s-box to each of the 4 bytes
    sub_bytes(word, N);

    // Perform the rcon operation on the msb of the output word and xor the rcon output with the first byte
    word[0] ^= RCON[rconItrValue];
}

void expand_key(const u_char *cipherKey, u_char *keySchedule){
    int createdBytes = HEXBASE, rconItrVal = 1, j;
    u_char temp[N];

    // copy the cipher key as the first 16 bytes of the key schedule
    memcpy(keySchedule, cipherKey, HEXBASE);

    while (createdBytes < KEYSIZE) {
        memcpy(temp, keySchedule + createdBytes - N, N);
        scheduler(temp, rconItrVal);
        rconItrVal++;
        xor_oprn(temp, keySchedule + createdBytes - HEXBASE, N);
        memcpy(keySchedule + createdBytes, temp, N);
        createdBytes += N;

        for (j=0; j< N-1; j++) {
            memcpy(temp, keySchedule + createdBytes - N, N);
            xor_oprn(temp,keySchedule + createdBytes - HEXBASE, N);
            memcpy(keySchedule + createdBytes, temp, N);
            createdBytes += N;
        }
    }
}

void shift_rows(u_char * state){
    u_char temp[HEXBASE];
    memcpy(temp, state, HEXBASE);
    for (int i = 0; i < HEXBASE; i++)
        state[i] = temp[RSHIFT[i]];
}

void inv_shift_rows(u_char * state){
    u_char temp[HEXBASE];
    memcpy(temp, state, HEXBASE);
    for(int i=0; i<HEXBASE; i++)
        state[i] = temp[RSHIFT_INV[i]];
}

void mix_columns(u_char * state) {
    u_char operandA[N];
    u_char operandB[N];
    u_char hiBit;

    for (int i = 0; i < N; i++) {
        for (int j = 0; j < N; j++) {
            operandA[j] = state[j + N * i];
            hiBit = state[j + N * i] & 0x80;
            operandB[j] = state[j + N * i] << 1;
            if (hiBit == 0x80)
                operandB[j] ^= 0x1b;
        }

        state[0 + N * i] = operandB[0] ^ operandA[3] ^ operandA[2] ^ operandB[1] ^ operandA[1];
        state[1 + N * i] = operandB[1] ^ operandA[0] ^ operandA[3] ^ operandB[2] ^ operandA[2];
        state[2 + N * i] = operandB[2] ^ operandA[1] ^ operandA[0] ^ operandB[3] ^ operandA[3];
        state[3 + N * i] = operandB[3] ^ operandA[2] ^ operandA[1] ^ operandB[0] ^ operandA[0];
    }
}

u_char galois_multiplication(u_char operandA, u_char operandB) {
    u_char product = 0;
    u_char hiBit;
    for (int i = 0; i < 8; i++) {
        if ((operandB & 1) == 1)
            product ^= operandA;
        hiBit = operandA & 0x80;
        operandA <<= 1;
        if (hiBit == 0x80)
            operandA ^= 0x1b;
        operandB >>= 1;
    }
    return product;
}

void inv_mix_columns(u_char * state) {
    u_char operand[N];
    for (int i = 0; i < N; i++) {
        for (int j = 0; j < N; j++)
            operand[j] = state[j + N * i];
        state[0 + N * i] =
                galois_multiplication(operand[0], 14) ^ galois_multiplication(operand[3], 9) ^
                galois_multiplication(operand[2], 13) ^ galois_multiplication(operand[1], 11);

        state[1 + N * i] =
                galois_multiplication(operand[1], 14) ^ galois_multiplication(operand[0], 9) ^
                galois_multiplication(operand[3], 13) ^ galois_multiplication(operand[2], 11);

        state[2 + N * i] =
                galois_multiplication(operand[2], 14) ^ galois_multiplication(operand[1], 9) ^
                galois_multiplication(operand[0], 13) ^ galois_multiplication(operand[3], 11);

        state[3 + N * i] =
                galois_multiplication(operand[3], 14) ^ galois_multiplication(operand[2], 9) ^
                galois_multiplication(operand[1], 13) ^ galois_multiplication(operand[0], 11);
    }
}

void encrypt(const u_char * plainText, const u_char * cipherKey, u_char *cipherText){
    u_char keySchedule[KEYSIZE];
    expand_key(cipherKey, keySchedule);

    printf("--> Key Schedule: \n");
    for(int i=0; i<KEYSIZE; i++){
        if (i > 0){
            if (i % 4 == 0){
                printf(", ");
                if (i % 16 == 0)
                    printf("\n");
            }
        }
        printf("%02x", keySchedule[i]);
    }
    printf("\n\n");

    printf("--> ENCRYPTION PROCESS \n");
    printf("------------------------\n");
    memcpy(cipherText, plainText, HEXBASE);
    add_round_key(cipherText, keySchedule, 0);

    printf("Round 1\n");
    printf("---------\n");
    for(int i=0; i<HEXBASE; i++){
        if (i > 0){
            if (i % 4 == 0)
                printf(" ");
        }
        printf("%02x ", cipherText[i]);
    }
    printf("\n\n");

    for(int i=0; i<NR-1; i++){
        sub_bytes(cipherText, HEXBASE);
        shift_rows(cipherText);
        mix_columns(cipherText);
        add_round_key(cipherText, keySchedule, i+1);

        printf("Round %d\n", i+2);
        printf("---------\n");
        for(int j=0; j<HEXBASE; j++){
            if (j > 0){
                if (j % 4 == 0)
                    printf(" ");
            }
            printf("%02x ", cipherText[j]);
        }
        printf("\n\n");
    }

    sub_bytes(cipherText, HEXBASE);
    shift_rows(cipherText);
    add_round_key(cipherText, keySchedule, NR);

    printf("--> Cipher Text\n");
    printf("-----------------\n");
    for(int j=0; j<HEXBASE; j++){
        if (j > 0){
            if (j % 4 == 0)
                printf(" ");
        }
        printf("%02x ", cipherText[j]);
    }
    printf("\n\n");
}

void decrypt(const u_char * cipherText, const u_char * cipherKey, u_char *plainText){
    u_char keySchedule[KEYSIZE];
    expand_key(cipherKey, keySchedule);

    printf("--> DECRYPTION PROCESS \n");
    printf("------------------------\n");

    memcpy(plainText, cipherText, HEXBASE);
    add_round_key(plainText, keySchedule, NR);
    inv_shift_rows(plainText);
    inv_sub_bytes(plainText, HEXBASE);

    printf("Round 10\n");
    printf("---------\n");
    for(int i=0; i<HEXBASE; i++){
        if (i > 0){
            if (i % 4 == 0)
                printf(" ");
        }
        printf("%02x ", plainText[i]);
    }
    printf("\n\n");

    for(int i=0; i<NR-1; i++){
        add_round_key(plainText, keySchedule, (NR - 1) - i);
        inv_mix_columns(plainText);
        inv_shift_rows(plainText);
        inv_sub_bytes(plainText, HEXBASE);

        printf("Round %d\n", (NR - 1) - i);
        printf("---------\n");
        for(int j=0; j<HEXBASE; j++){
            if (j > 0){
                if (j % 4 == 0)
                    printf(" ");
            }
            printf("%02x ", plainText[j]);
        }
        printf("\n\n");
    }

    add_round_key(plainText, keySchedule, 0);

    printf("--> Plain Text\n");
    printf("-----------------\n");
    for(int j=0; j<HEXBASE; j++){
        if (j > 0){
            if (j % 4 == 0)
                printf(" ");
        }
        printf("%02x ", plainText[j]);
    }
    printf("\n\n");

}

void extract(u_char *buffer, char *textfile, int bufferSize){

    FILE *fileProc;
    unsigned hex;

    fileProc = fopen(textfile, "r");

    for(int i=0; i<bufferSize; i++){
        fscanf(fileProc, "%2x", &hex);
        buffer[i] = (u_char)hex;
    }

    fclose(fileProc);

}

void printBuffer(u_char *buffer, int bufferSize){
    for(int i=0; i<bufferSize; i++)
        printf("%02x ", buffer[i]);
    printf("\n");
}

void aes_processing(char *plaintextFile, char *keyFile){
    u_char plainTextBuffer[HEXBASE];
    u_char cipherKeyBuffer[HEXBASE];
    u_char cipherTextBuffer[HEXBASE];

    printf("--> PlainText: \n");
    extract(plainTextBuffer, plaintextFile, HEXBASE);
    printBuffer(plainTextBuffer, HEXBASE);

    printf("--> Key: \n");
    extract(cipherKeyBuffer, keyFile, HEXBASE);
    printBuffer(cipherKeyBuffer, HEXBASE);
    printf("\n");

    extract(SBOX_BUFFER, "aes_sbox.txt", BUFFSIZE);

    encrypt(plainTextBuffer, cipherKeyBuffer, cipherTextBuffer);

    extract(INV_SBOX_BUFFER, "aes_inv_sbox.txt", BUFFSIZE);

    decrypt(cipherTextBuffer, cipherKeyBuffer, plainTextBuffer);

    printf("End of Processing\n");
}


