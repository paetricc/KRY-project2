/********************************************************
 * Autor: Tomáš Bártů
 * Login: xbartu11 (230653)
 * Email: xbartu11@stud.fit.vutbr.cz
 *
 * KRY Projekt 2: MAC za použití SHA-256 & Lengthextension attack
 *
 * Zdroj pro implementaci hashovacího algoritmu sha256:
 *   -[1] http://dx.doi.org/10.6028/NIST.FIPS.180-4
 * Zdroje pro pochopení length extension attacku:
 *   -[2] https://lord.io/length-extension-attacks/
 *   -[3] https://bostik.iki.fi/dc4420/size_t-does-matter--hash-length-extensions.pdf
 *   -[4] https://www.javacodegeeks.com/2012/07/hash-length-extension-attacks.html
 *   -[5] https://github.com/viensea1106/hash-length-extension
 *******************************************************/

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
 * Funkce, která přípravý potřebná data pro spuštění funkce hash()
 */
void do_hash();

/**
 * Funkce, která přípravý potřebná data pro spuštění funkce mac()
 *
 * @param key tajný klíč
 */
void do_mac(const char *key);

/**
 * Funkce, která přípravý potřebná data pro spuštění funkce mac_verify()
 *
 * @param key tajný klíč
 * @param chs hash, který má být zkontrolován
 * @return
 */
bool do_mac_verify(const char *key, const char *chs);

/**
 * Funkce, která přípravý potřebná data pro spuštění funkce extension()
 *
 * @param chs hash původní zprávy
 * @param msg text, který má být přidán
 * @param num délka tajného klíče
 */
void do_extension(const char *chs, char* msg, const int num);

/**
 * Funkce, která vytvoří padding, respektive paměť do které vloží padding. Padding vypadá následovně
 *
 *       1           2              3
 * +----------+-------------+-------------+
 * |0b10000000| nulové byty | délka textu |
 * +----------+-------------+-------------+
 * |                                      |
 * |<---------- 512 - text_len ---------->|
 *
 * kde:
 * 1. Byte obsahující nejdříve bitovou 1 a následně je doplněn bitovými 0
 * 2. Odpovídající počet bytů obsahující pouze bitové 0, celkový počet bitových nul, která tato část obsahuje
 *    je dána vzorcem: k_bits = (448 - l_bits - 1) % 512, kde l_bits je délka textu v bitech.
 * 3. Místo pro uložení délky textu je 8B, kde je tato hodnota v bitech a je uložena v big endian formátu.
 *
 * Po naplnění paměti paddingem je vrácen ukazatel na tuto paměť.
 *
 * @param text_len délka textu
 * @param padding_len proměnná pro uložení velikosti paddingu
 * @return ukazatel na nově vytvořenou paměť
 */
unsigned char* do_padding(size_t text_len, size_t *padding_len);

/**
 * Funkce, která vytvoří novou paměť a uloží do ní za sebe obsah paměti, na které ukazují po řadě ukazatele
 * z argumentů funkce. Výsledná paměť vypadá následovně
 *
 * +---------------+---------------+
 * |     mem1      |     mem2      |
 * +---------------+---------------+
 * |                               |
 * |<--- size1 --->|<--- size2 --->|
 *
 * @param mem1 ukazatel na první paměť
 * @param size1 velikost první paměti
 * @param mem2 ukazatel na druhou paměť
 * @param size2 velikost druhé paměti
 * @return ukazel na nově vytvořenou paměť
 */
unsigned char* do_mem_merge(unsigned char* mem1, size_t size1, unsigned char* mem2, size_t size2);

/**
 * Funkce, která alokuje paměť dle zadané velikost pomocí funkce calloc(), která inicialuzuje alokovanou paměť na 0.
 * V případě chyby alokace na standardní chybový výstup vypíše zadaný chybový text. Výsledná paměť vypadá následovně:
 *
 * +--------------------------------+
 * | size | size |size | size | ... |
 * +--------------------------------+
 * |                                |
 * |<---------- mem_size ---------->|
 *
 * @param mem_size velikost výsledné paměti
 * @param size velikost jedné položky v paměti
 * @param error_msg chybová hláška
 * @return ukazatel na nově vytvořenou paměť
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
 * pomocí funkce MAC = SHA256(SECRET_KEY + MSG).
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
bool mac_verify(uint32_t hash[8], const char *chs_hash);

/**
 * Funkce, která aplikuje length extension attack na algoritmus SHA-256.
 * Základní schéma útoku je:
 *
 *                              |<----------- extent ---------->|
 *                              |                               |
 * +------+------+--------------+-----------+-------------------+
 * | klíč | text | text padding | extension | extension padding |
 * +------+------+--------------+-----------+-------------------+
 *                              |                               |
 *                              |<--------- extent_len -------->|
 *
 * kde tento útok sestává z kroků:
 * 1. Je známa délka klíče, původní text a výsledný hash chs_hash.
 * 2. Za paměť o velikosti klíče se připojí původní text.
 * 3. Následně se vytvoří padding a opět se připojí
 * 4. Nyní se připojí nový text(extension)
 * 5. Opět se vypočítá padding respektive extension padding
 * 6  Vytvoří se paměť obsahující pouze extension a extension padding, tedy paměť extent o velikosti extent_len
 * 7. Aplikuje hashovací algoritmus s následujícími parametry: sha256(extent, hash, extent_len, chs_hash).
 *
 * Tato funkce vychází z informací ze zdrojů [2], [3], [4] a [5].
 *
 * @param key_len délka klíče
 * @param text vstupní text
 * @param chs_hash znamý hash
 * @param extension text, který má být přidán
 */
void extension(const uint32_t key_len, char *text, const char *chs_hash, char *extension);

/**
 * Funkce, která převede hash z řetězcové podoby do pole
 *
 * @param chs_hash Řetězec obsahující hash v hexadecimální podobě
 * @param H pole pro uložení výsledného hashe
 */
void hash_to_uint(const char *chs_hash, uint32_t hash[8]);

/**
 * Funkce, která zkontroluje zda vstupní hashe jsou identické
 *
 * @param H_act první hash (aktuální)
 * @param H_init druhý hash (iniciální)
 * @return false pokud se nerovnají jinak true
 */
bool is_hash_equal(const uint32_t H_act[8], const uint32_t H_init[8]);

/**
 * Funkce, která ze standardního vstupu přečte vstupní text.
 *
 * @param text_len proměnná pro uložení velikosti textu
 * @return ukazatel na paměť s textem
 */
char* read_data(ssize_t *text_len);

/**
 * Funkcé, která vypíše SHA-256 hash dle regulárního výrazu ^[A-Fa-f0-9]{64}$
 *
 * @param hash Hash, který má být vypsán
 */
void print_hash(const uint32_t hash[8]);

/**
 * Funkce, která vypíše v hexadecimální podobě (0\xXX, kde XX je hexadecimální podoba znaku) obsah paměti.
 *
 * @param data ukazatel na paměť
 * @param size velikost paměti (počet znaků, který bude vypsán)
 */
void print_memory(const unsigned char* data, size_t size);

/**
 * Funkce, která vypíše nápovědu programu.
 */
void print_help();

#endif //KRY_H
