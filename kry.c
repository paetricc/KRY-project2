#include "kry.h"

void print_bits_be(size_t const size, void const * const ptr) {
    unsigned char *b = (unsigned char*) ptr;
    unsigned char byte;
    int i, j;

    for (i = 0; i < size; i++) {
        for (j = 7; j >= 0; j--) {
            byte = (b[i] >> j) & 1;
            printf("%u", byte);
        }
        if ((i + 1) % 4 == 0) {
            printf("\n"); // Nový řádek po každých čtyřech bytech
        } else {
            printf(" "); // Mezera mezi byty
        }
    }
}

void print_bits_le(size_t const size, void const * const ptr) {
    unsigned char *b = (unsigned char*) ptr;
    unsigned char byte;
    int i, j;

    for (i = size-1; i >= 0; i--) {
        for (j = 7; j >= 0; j--) {
            byte = (b[i] >> j) & 1;
            printf("%u", byte);
        }
        if (i > 0) {
            //printf(" "); // Mezera mezi byty
        } else {
            printf("\n"); // Nový řádek po posledním bytu
        }
    }
}

int main(int argc, char** argv) {
    int opt;
    char operation = 0;
    char *key=NULL, *chs=NULL, *msg=NULL;
    int num = -1;

    while ((opt = getopt(argc, argv, "csve:k:m:n:a:")) != -1) {
        switch (opt) {
            case 'c':
            case 's':
            case 'v':
            case 'e':
                if (operation == 0) {
                    operation = opt;
                } else {
                    fprintf(stderr, "Lze použít pouze jeden z přepínačů -c, -s, -v nebo -e.\n");
                    exit(EXIT_FAILURE);
                }
                break;
            case 'k':
                key = optarg;
                break;
            case 'm':
                chs = optarg;
                break;
            case 'n':
                num = atoi(optarg);
                break;
            case 'a':
                msg = optarg;
                break;
            default:
                fprintf(stderr, "Neznámý parametr: -%c\n", opt);
                exit(EXIT_FAILURE);
        }

        char *text = NULL;
        size_t buffer_size = 0;
        ssize_t input_length = 0;
        switch (operation) {
            case 'c':
                input_length = getdelim(&text, &buffer_size, EOF, stdin);
                if(input_length == -1) {
                    fprintf(stderr, "Chyba při provádění funkce getdelim().");
                    exit(EXIT_FAILURE);
                }
                sha256(text);
                free(text);
                break;
            case 's':
                if(!key) {
                    fprintf(stderr, "Nebyl zadán klíč pro výpočet MAC.\n");
                    exit(EXIT_FAILURE);
                }
                break;
            case 'v':
                if(!key) {
                    fprintf(stderr, "Nebyl zadán klíč pro ověření.\n");
                    exit(EXIT_FAILURE);
                }
                if(!chs) {
                    fprintf(stderr, "Nebyl zadán MAC pro ověření.\n");
                    exit(EXIT_FAILURE);
                }
                break;
            case 'e':
                if(!chs) {
                    fprintf(stderr, "Nebyl zadán MAC pro útok.\n");
                    exit(EXIT_FAILURE);
                }
                if(num == -1) {
                    fprintf(stderr, "Nebyla zadána délka klíče pro útok.\n");
                    exit(EXIT_FAILURE);
                }
                if(!msg) {
                    fprintf(stderr, "Nebyl zadán MAC pro útok.\n");
                    exit(EXIT_FAILURE);
                }
                break;
            default:
                fprintf(stderr, "Nebyla zvolena žádná operace.\n");
                exit(EXIT_FAILURE);
        }
    }
    return EXIT_SUCCESS;
}

size_t utf8_strlen_bytes(const char *str) {
    size_t len = 0;
    while (*str) {
        if ((*str & 0x80) == 0) {          // 0xxxxxxx
            len += 1;
        } else if ((*str & 0xE0) == 0xC0) { // 110xxxxx 10xxxxxx
            len += 2;
        } else if ((*str & 0xF0) == 0xE0) { // 1110xxxx 10xxxxxx 10xxxxxx
            len += 3;
        } else if ((*str & 0xF8) == 0xF0) { // 11110xxx 10xxxxxx 10xxxxxx 10xxxxxx
            len += 4;
        }
        ++str;
    }
    return len;
}

void sha256(const char *text) {
    size_t l_bytes = utf8_strlen_bytes(text);
    size_t l_bits = l_bytes * BYTE;
    int k = (448 - l_bits - 1) % 512;

    size_t padding = l_bytes + 1 + (k / BYTE) + 8;
    printf("Alokace pro padded_msg, požadovaná velikost: %zu bytes\n", padding);
    unsigned char *padded_msg = (unsigned char *) calloc(padding, sizeof(unsigned char));
    if(!padded_msg) {
        fprintf(stderr, "Chyba ve funkci calloc().\n");
    } else {
        printf("Alokace pro padded_msg úspěšná, velikost: %zu bytes\n", padding);
    }

    if(!padded_msg) {
        fprintf(stderr, "Chyba ve funkci calloc().");
        exit(EXIT_FAILURE);
    }
    memcpy(padded_msg, text, l_bytes);
    padded_msg[l_bytes] = 0x80;
    for (int i = 0; i < 8; i++) {
        padded_msg[padding - 1 - i] = (uint8_t)(l_bits >> (i * 8));
    }
    //print_bits(padding, padded_msg);
    int r = padding*8/512;
    printf("Alokace pro blocks, požadovaný počet: %d, velikost: %zu bytes\n", r * 16, r * 16 * sizeof(uint32_t));

    uint32_t (*blocks)[16] = (uint32_t *) calloc(r * 16, sizeof(uint32_t));
    if(!blocks) {
        fprintf(stderr, "Chyba ve funkci calloc().\n");
    } else {
        printf("Alokace pro blocks úspěšná, počet: %d, velikost: %zu bytes\n", r * 16, r * 16 * sizeof(uint32_t));
    }

    // Kopírujeme data do bloků
    for (size_t row = 0; row < r; ++row) {
        size_t bytes_to_copy = 64;
        memcpy(blocks[row], padded_msg + row * 64, bytes_to_copy);
    }

    for (size_t row = 0; row < r; ++row) {
        //print_bits(64,blocks[row]);
    }

    u_int32_t H[8] = {
            0x6a09e667,
            0xbb67ae85,
            0x3c6ef372,
            0xa54ff53a,
            0x510e527f,
            0x9b05688c,
            0x1f83d9ab,
            0x5be0cd19
    };
    uint32_t W[64];
    for (int i = 0; i < r; ++i) {
        for (int j = 0; j <= 15; ++j) {
            W[j] = htonl(blocks[i][j]);
        }
        for (int j = 16; j <= 63; ++j) {
            W[j] = SIGMA1(W[j-2]) + W[j-7] + SIGMA0(W[j-15]) + W[j-16];
        }

        uint32_t a,b,c,d,e,f,g,h;
            a = H[0];
            b = H[1];
            c = H[2];
            d = H[3];
            e = H[4];
            f = H[5];
            g = H[6];
            h = H[7];

        for (int t = 0; t <= 63; ++t) {
            uint32_t t_1, t_2;
            t_1 = h + SUM1(e) + CH(e,f,g) + K[t] + W[t];
            t_2 = SUM0(a) + MAJ(a,b,c);
            h=g;
            g=f;
            f=e;
            e=d+t_1;
            d=c;
            c=b;
            b=a;
            a=t_1+t_2;

        }

        H[0] = a + H[0];
        H[1] = b + H[1];
        H[2] = c + H[2];
        H[3] = d + H[3];
        H[4] = e + H[4];
        H[5] = f + H[5];
        H[6] = g + H[6];
        H[7] = h + H[7];
    }

    for (int i = 0; i < 8; i++) {
        printf("%08x", H[i]);
    }
    printf("\n");

    free(padded_msg);
    free(blocks);
}