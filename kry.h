#ifndef KRY_H
#define KRY_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <limits.h>
#include <stdbool.h>

#define SEGMENT_LEN 64 // velikost segmentu v bytech
#define HASH_LEN    64 // velikost hashe v bytech

// následující makra vychází z definic z [1] ze sekce 4.1.2, kde jednotlivé z rovnic i s jejich očíslováním jsou:
#define CH(x,y,z)  ((x & y) ^ ((~x) & z))                      // (4.2)
#define MAJ(x,y,z) ((x & y) ^ (x & z) ^ (y & z))               // (4.3)
#define SUM0(x)    ((ROTR(x,2)) ^ (ROTR(x,13)) ^ (ROTR(x,22))) // (4.4)
#define SUM1(x)    ((ROTR(x,6)) ^ (ROTR(x,11)) ^ (ROTR(x,25))) // (4.5)
#define SIGMA0(x)  ((ROTR(x,7)) ^ (ROTR(x,18)) ^ (SHR(x,3)))   // (4.6)
#define SIGMA1(x)  ((ROTR(x,17)) ^ (ROTR(x,19)) ^ (SHR(x,10))) // (4.7)
// kde jednotlivé operace vychází z [1] ze 3.2
#define SHR(x,n)   (x >> n)                                    // bod 3
#define ROTR(x,n)  ((x >> n) | (x << (32 - n)))                // bod 4
// tyto konstanty vychází [1] ze sekce 4.2.2
static const uint32_t K[64] = {
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};
// tyto iniciální hodnoty hashe vychází z [1] ze sekce 5.3.3
static const uint32_t H_0[8] = {
        0x6a09e667,
        0xbb67ae85,
        0x3c6ef372,
        0xa54ff53a,
        0x510e527f,
        0x9b05688c,
        0x1f83d9ab,
        0x5be0cd19
};

/**
 *
 */
void do_hash();

/**
 *
 * @param key
 */
void do_mac(const char *key);

/**
 *
 * @param key
 * @param chs
 * @return
 */
bool do_mac_verify(const char *key, const char *chs);

/**
 *
 * @param chs
 * @param msg
 * @param num
 */
void do_extension(const char *chs, char* msg, const int num);

/**
 *
 * @param text_len
 * @param padding_len
 * @return
 */
unsigned char* do_padding(size_t text_len, size_t *padding_len);

/**
 *
 * @param mem1
 * @param size1
 * @param mem2
 * @param size2
 * @return
 */
unsigned char* do_mem_merge(unsigned char* mem1, size_t size1, unsigned char* mem2, size_t size2);

/**
 *
 * @param mem_size
 * @param size
 * @param error_msg
 * @return
 */
unsigned char* do_calloc(size_t mem_size, size_t size, const char *error_msg);

/**
 * Funkce pro výpočet sha256 ze zadanáho textu
 *
 * @param text vstupní text
 * @param hash pole pro uložení výsledného hashe
 */
void sha256(unsigned char *text, uint32_t hash[8], ssize_t text_len, const uint32_t H[8]);

/**
 * Funkce pro výpočet MAC (Message Authentication Code) pomocí sha256 kombinací zadaného textu a tajného klíče
 * pomocí funkce MAC = 𝑆𝐻𝐴256(𝑆𝐸𝐶𝑅𝐸𝑇_𝐾𝐸𝑌 + 𝑀𝑆𝐺).
 *
 * @param text vstupní text
 * @param key tajný klíč
 * @param hash pole pro uložení výsledného mac
 */
void mac(char *text, const char *key, uint32_t hash[8], size_t text_len);

/**
 * Funkce pro porovnání zda jsou zadané hashe shodné, kde
 * - první hash je zadán v poli datového typu uint32_t
 * - druhý hash je zadán v řetězové podobě
 *
 * @param hash hash vrácený funkcí sha256()
 * @param chs_hash kontrolní hash
 * @return 0 pokud se hashe shodují jinak 1
 */
bool verify_mac(uint32_t hash[8], const char *chs_hash);

/**
 *
 * @param key_len
 * @param text
 * @param chs_hash
 * @param extension
 */
void extension(const uint32_t key_len, char *text, const char *chs_hash, char *extension);

/**
 *
 * @param chs_hash
 * @param H
 */
void hash_to_uint(const char *chs_hash, uint32_t hash[8]);

/**
 *
 * @param H_act
 * @param H_init
 * @return
 */
bool is_hash_equal(const uint32_t H_act[8], const uint32_t H_init[8]);

/**
 *
 * @param text_len
 * @return
 */
char* read_data(ssize_t *text_len);

/**
 *
 * @param hash
 */
void print_hash(const uint32_t hash[8]);

/**
 *
 * @param data
 * @param size
 */
void print_memory(const unsigned char* data, size_t size);

/**
 *
 */
void print_help();

#endif //KRY_H
