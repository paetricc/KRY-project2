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

#include "kry.h"

int main(int argc, char** argv) {
    int opt;
    char operation = 0;
    char *key=NULL, *chs=NULL, *msg=NULL;
    int num = -1;

    if (argc == 1) {
        print_help();
        return EXIT_FAILURE;
    }

    while ((opt = getopt(argc, argv, "csvek:m:n:a:")) != -1) {
        switch (opt) {
            case 'c':
            case 's':
            case 'v':
            case 'e':
                if (operation == 0) { // pokud nebyla dosud zaznamenána operace
                    operation = opt;  // tak se uloží
                } else {              // jinak se ukončí program
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
    }

        switch (operation) {
            case 'c':
                do_hash();
                break;
            case 's':
                do_mac(key);
                break;
            case 'v':
                return do_mac_verify(key, chs);
            case 'e':
                do_extension(chs, msg, num);
                break;
            default:
                fprintf(stderr, "Nebyla zvolena žádná operace.\n");
                exit(EXIT_FAILURE);
        }
        return EXIT_SUCCESS;
}

void do_hash() {
    ssize_t text_len = 0;
    char *text = read_data(&text_len); // načtení vstupních dat

    uint32_t hash[8]; // paměť pro uložení výsledného 256bitového hashe
    sha256((unsigned char*)text, hash, text_len, H_0); // výpočet hashe algoritmem sha256
    print_hash(hash);
    free(text);
}

void do_mac(const char *key) {
    if(!key) {
        fprintf(stderr, "Nebyl zadán klíč pro výpočet MAC.\n");
        exit(EXIT_FAILURE);
    }

    ssize_t text_len = 0;
    char *text = read_data(&text_len); // načtení vstupních dat

    uint32_t hash[8]; // paměť pro uložení výsledného 256bitového hashe
    mac(text, key, hash, text_len); // výpočet MAC (Message Authentication Code)
    print_hash(hash);
    free(text);
}

bool do_mac_verify(const char *key, const char *chs) {
    if(!key) {
        fprintf(stderr, "Nebyl zadán klíč pro ověření.\n");
        exit(EXIT_FAILURE);
    }
    if(!chs) {
        fprintf(stderr, "Nebyl zadán MAC pro ověření.\n");
        exit(EXIT_FAILURE);
    }

    ssize_t text_len = 0;
    char *text = read_data(&text_len); // načtení vstupních dat

    uint32_t hash[8]; // paměť pro uložení výsledného 256bitového hashe
    mac(text, key, hash, text_len); // výpočet MAC (Message Authentication Code)
    free(text);

    return mac_verify(hash, chs); // ověření shodnosti hashů
}

void do_extension(const char *chs, char* msg, const int num) {
    if(!chs) {
        fprintf(stderr, "Nebyl zadán MAC pro útok.\n");
        exit(EXIT_FAILURE);
    }
    if(!msg) {
        fprintf(stderr, "Nebyl zadán MAC pro útok.\n");
        exit(EXIT_FAILURE);
    }
    if(num == -1) {
        fprintf(stderr, "Nebyla zadána délka klíče pro útok.\n");
        exit(EXIT_FAILURE);
    }

    ssize_t text_len = 0;
    char *text = read_data(&text_len); // načtení vstupních dat

    extension(num, text, chs, msg); // provedení LEA (Length Extension Attack)
    free(text);
}

unsigned char* do_padding(size_t text_len, size_t *padding_len) {
    uint64_t l_bytes = text_len;                // délka textu v bytech
    uint64_t l_bits  = (l_bytes) * CHAR_BIT;    // délka textu v bitech
    uint32_t k_bits = (448 - l_bits - 1) % 512; // výpočet počtu nul k přidání za text
    // výpočet délky paddingu v bytech (byte obsahující 1 + počet bytů s nulami + 8 bytů pro délku textu)
    *padding_len = 1 + (k_bits / CHAR_BIT) + 8;
    unsigned char *padding = do_calloc(*padding_len, sizeof(unsigned char), "Chyba alokace paměti ve funkci do_padding()");
    unsigned char padded_one = 0x80;
    memcpy(padding, &padded_one, sizeof(unsigned char)); // vložení bitové 1 + 7 bitových 0, respektive 10000000
    uint64_t l_bits_be = htobe64(l_bits); // převedení délky zprávy v bitech na big-endian
    memcpy(&padding[*padding_len - 8], &l_bits_be, sizeof(uint64_t)); // vložení délky zprávy v big-endian

    return padding;
}

unsigned char* do_mem_merge(unsigned char* mem1, size_t size1, unsigned char* mem2, size_t size2) {
    unsigned char *merged_mem = do_calloc(size1 + size2, sizeof(unsigned char), "Chyba alokace paměti ve funkci do_mem_merge()");

    memcpy(merged_mem, mem1, size1);
    memcpy(&merged_mem[size1], mem2, size2);

    return merged_mem;
}

unsigned char* do_calloc(size_t mem_size, size_t size, const char *error_msg) {
    unsigned char *memory = calloc(mem_size, size);
    if (!memory) {
        fprintf(stderr, "%s\n", error_msg);
        exit(EXIT_FAILURE);
    }
    return memory;
}

void sha256(unsigned char *text, uint32_t hash[8], ssize_t text_len, const uint32_t H_init[8]) {
    // paměť pro uchování textu
    unsigned char *text_mem = do_calloc(text_len, sizeof(unsigned char), "Chyba alokace paměti ve funkci sha256()");
    memcpy(text_mem, text, text_len);

    unsigned char *padded_text = NULL;
    size_t padding_len = 0;
    // pokud iniciální hodnoty hashe souhlasí s iniciálními hodnotami hashe z [1]
    if (is_hash_equal(H_init, H_0)) {
        // tak se vytvoří padding a připojí se za text
        unsigned char *padding = do_padding(text_len, &padding_len);
        padded_text = do_mem_merge(text_mem, text_len, padding, padding_len);
        free(padding);
    } else {
        // jinak se předpokládá, že padding je již v textu
        padded_text =  do_calloc(text_len, sizeof(unsigned char), "Chyba alokace paměti ve funkci sha256()");
        memcpy(padded_text, text_mem, text_len);
    }
    free(text_mem);

    uint32_t N = (text_len + padding_len) / 64; // počet 512bitových segmentů textu (jinak také k_bytes*CHAR_BIT/512)
    uint32_t (*segments)[16] = calloc(N * 16, sizeof(uint32_t));
    if(!segments) { // kontrola zda proběhla alokace paměti v pořádku
        fprintf(stderr, "Chyba ve funkci calloc().\n");
        exit(EXIT_FAILURE);
    }
    // do každého segmentu se vloží odpovídající 64bytů zprávy
    for (uint32_t seg_num = 0; seg_num < N; seg_num++)
        memcpy(segments[seg_num], padded_text + seg_num * SEGMENT_LEN, SEGMENT_LEN);

    // nyní jsou v paměti připravena všechna data v požadovaném formátu a je možné aplikovat algoritmus pro výpočet hash
    // následující algoritmus vychází z [1] ze sekce 6.2

    // vložení počátečních hodnot hash (sekce 6.2.1)
    uint32_t H[8];
    for (int i = 0; i < 8; i++)
        H[i] = H_init[i];
    // hashovací algoritmus (sekce 6.2.2)
    uint32_t W[64];
    for (uint32_t i = 0; i < N; ++i) {
        for (int j = 0; j <= 15; ++j)
            W[j] = htobe32(segments[i][j]); // převod do big endian pro správné chování bitových operací
        for (int j = 16; j <= 63; ++j)
            W[j] = SIGMA1(W[j - 2]) + W[j - 7] + SIGMA0(W[j - 15]) + W[j - 16];

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
    // překopírování výsledných čásí hashe
    for (int i = 0; i < 8; i++)
        hash[i] = H[i];

    free(padded_text);
    free(segments);
}

void mac(char *text, const char *key, uint32_t hash[8], size_t text_len) {
    size_t key_length = strlen(key); // délka klíče
    size_t total_length = key_length + text_len; // célková délka textu i s klíčem
    // alokace paměti pro spojení klíče a textu
    unsigned char *key_text = do_calloc(total_length, sizeof(unsigned char), "Chyba alokace paměti ve funkci mac()");
    memcpy(key_text, key, key_length);             // překopírování klíče do paměti
    memcpy(&key_text[key_length], text, text_len); // překopírování textu za klíč do paměti
    sha256(key_text, hash, total_length, H_0);     // hashování nového textu
    free(key_text);
}

bool mac_verify(uint32_t hash[8], const char *chs_hash) {
    // kontrola zda vstupní řetězec má požadovanou délku
    if (strlen(chs_hash) != HASH_LEN) {
        fprintf(stderr, "Vstupní hash nemá požadovanou délku.\n");
        exit(EXIT_FAILURE);
    }
    uint32_t chs_hash_arr[8];
    hash_to_uint(chs_hash, chs_hash_arr); // převod hashe z řetězcové podoby do pole
    for (int i = 0; i < 8; i++)
        if (hash[i] != chs_hash_arr[i])
            return true; // pokud některá část obou hashů není shodná vratí se 1

    return false; // jinak se vrátí 0
}

void extension(const uint32_t key_len, char *text, const char *chs_hash, char *extension) {
    uint64_t text_len = strlen(text);
    // alokace poměti pro klíč, respektive pouze pro jeho velikost
    unsigned char *key_mem = do_calloc(key_len, sizeof(unsigned char), "Chyba alokace paměti ve funkci extension()");
    // spojení prázdného klíče a textu
    unsigned char* key_text_mem = do_mem_merge(key_mem, key_len, (unsigned char *)text, text_len);
    free(key_mem);
    // vytvoření paddingu a připojení ho za text s klíčem
    size_t padding_len = 0;
    unsigned char* padding = do_padding(strlen(text) + key_len, &padding_len);
    unsigned char* padded_text = do_mem_merge(key_text_mem, key_len + text_len, padding, padding_len);
    free(key_text_mem);
    // vytvoření paměti pro přídavný text
    size_t extension_len = strlen(extension);
    unsigned char *extension_mem = do_calloc(extension_len, sizeof(unsigned char), "Chyba alokace paměti ve funkci extension()");
    memcpy(extension_mem, extension, extension_len);
    // připojení textu s paddingem a přídavného textu
    unsigned char* padded_text_extension = do_mem_merge(padded_text, key_len + text_len + padding_len, extension_mem, extension_len);
    free(padded_text);
    free(extension_mem);
    // vytvoření paddingu a připojeního za text s paddingem a přídavným textem
    size_t extension_padding_len = 0;
    unsigned char* extension_padding = do_padding(key_len + text_len + padding_len + extension_len, &extension_padding_len);
    unsigned char* extension_padded_text = do_mem_merge(padded_text_extension, key_len + text_len + padding_len + extension_len, extension_padding, extension_padding_len);
    free(padded_text_extension);
    free(extension_padding);
    // vytvoření výsledného textu pro aplikaci LEA (Length Extension Attack)
    unsigned char *extent =  do_calloc(extension_len + extension_padding_len, sizeof(unsigned char), "Chyba alokace paměti ve funkci extension()");
    // z textu se využije pouze část z přídavným textem a následným paddingem
    memcpy(extent, &extension_padded_text[key_len + text_len + padding_len], extension_len + extension_padding_len);
    free(extension_padded_text);
    // převod hashe z řetězcové podoby do pole
    uint32_t H[8];
    hash_to_uint(chs_hash, H);
    // aplikace LEA s danými novými iniciálními hodnotami hashe
    uint32_t hash[8];
    sha256(extent, hash, extension_len + extension_padding_len, H);

    print_hash(hash);
    printf("%s", text);
    print_memory(padding, padding_len);
    printf("%s\n", extension);

    free(padding);
    free(extent);
}

void hash_to_uint(const char *chs_hash, uint32_t hash[8]) {
    for (int i = 0; i < 8; i++)
        sscanf(chs_hash + i * CHAR_BIT, "%08x", &hash[i]);
}

bool is_hash_equal(const uint32_t H_act[8], const uint32_t H_init[8]) {
    for (int i = 0; i < 8; i++)
        if (H_act[i] != H_init[i])
            return false; // alespoň jedna hodnota se liší

    return true; // všechny hodnoty jsou stejné
}

char* read_data(ssize_t *text_len) {
    char *text = NULL;
    size_t buffer_size = 0;
    *text_len = getdelim(&text, &buffer_size, EOF, stdin);
    if (*text_len == -1) {
        fprintf(stderr, "Chyba při provádění funkce getdelim().");
        free(text);
        exit(EXIT_FAILURE);
    }
    return text;
}

void print_hash(const uint32_t hash[8]) {
    for (int i = 0; i < 8; i++)
        printf("%08x", hash[i]);
    printf("\n");
}

void print_memory(const unsigned char* data, size_t size) {
    for (size_t i = 0; i < size; i++)
        printf("\\x%02x", data[i]);
}

void print_help() {
    printf("NÁZEV\n");
    printf("    kry - Implementace hashovacího algoritmu SHA-256 a útoku na něj.\n\n");

    printf("SYNOPSIS\n");
    printf("    echo -ne \"<vstupni_zprava>\" | ./kry -c\n");
    printf("    echo -ne \"<vstupni_zprava>\" | ./kry -s -k <klic>\n");
    printf("    echo -ne \"<vstupni_zprava>\" | ./kry -v -k <klic> -m <mac>\n");
    printf("    echo -ne \"<vstupni_zprava>\" | ./kry -e -n <delka_klice> -a <pridany_text> -m <mac>\n\n");

    printf("POPIS\n");
    printf("    Program implementující hashovací algoritmus SHA-256 a umožňující: \n");
    printf("            * generování hashe ze vstupní zprávy,\n");
    printf("            * generování MAC (Message Authentication Code) pro vstupní zprávu a tajný klíč,\n");
    printf("            * ověření MAC (Message Authentication Code) pro vstupní zprávu a tajný klíč,\n");
    printf("            * aplikace length extension attacku pro generování MAC.\n\n");

    printf("MOŽNOSTI\n");
    printf("    -c\n");
    printf("          Vypočet hashe vstupní zprávy.\n");
    printf("    -s -k <klic>\n");
    printf("          Generování MAC (Message Authentication Code) ze vstupní zprávy a tajného klíče.\n");
    printf("    -v -k <klic> -m <mac>\n");
    printf("          Ověření MAC pro vstupní zprávu a tajný klíč.\n");
    printf("    -e -n <delka_klice> -a <pridany_text> -m <mac>\n");
    printf("          Aplikace length extension attacku.\n\n");

    printf("PŘÍKLADY\n");
    printf("    echo -ne \"zprava\" | ./kry -c\n");
    printf("    echo -ne \"zprava\" | ./kry -s -k heslo\n");
    printf("    echo -ne \"zprava\" | ./kry -v -k heslo -m 23158796a45a9392951d9a72dffd6a539b14a07832390b937b94a80ddb6dc18e\n");
    printf("    echo -ne \"zprava\" | ./kry -e -n 5 -a ==message -m 23158796a45a9392951d9a72dffd6a539b14a07832390b937b94a80ddb6dc18e\n\n");

    printf("AUTOR\n");
    printf("    Vytvořil Tomáš Bártů, xbartu11@stud.fit.vutbr.cz\n");
}
