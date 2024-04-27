# KRY Projekt 2: MAC za použití SHA-256 & Lengthextension attack
* Autor: Tomáš Bártů
* Login: xbartu11 (230653)
* Email: xbartu11@stud.fit.vutbr.cz

## Popis
Cílem projektu je implementace hashovacího algoritmu SHA-256 a s tím související generátor MAC 
(Message Authentication Code) pomocí tohoto algoritmu a tajného klíče a zároveň projekt umožňuje ověření MAC. 
Další částí projektu je realizace length extension attacku, kde tento útok umožňuje přepočítání MAC bez znalosti tajného 
klíče.

## Implementace
Níže jsou popsány základní části implementace. Detailnější popis implementace se nachází v komentářové podobě v 
souborech **kry.c/h**, přičemž v hlavičkovém souboru jsou popsány jednotlivé funkce.

### SHA-256
Implementace hashovacího algoritmu SHA-256 je založena na specifikaci [1]. Algoritmus iterativně zpracovává bloky dat 
o velikosti 512 bitů, na které aplikuje danou posloupnost rovnic a bitových operací (AND, OR, XOR, rotace, posuv, ...). 
Výsledkem těchto operací je 256bitový hash, který je počítán následovně:

1. **Inicializace:** Na počátku výpočtu jsou nastaveny iniciální hodnoty hashe dle standardu. 
2. **Zpracování bloků:** Podmínkou pro aplikaci hlavní smyčky je nutnost, aby velikost textu byla násobkem 512bitů. 
   Text je tedy doplněn o padding, respektive je za text připojena bitová 1, za ní je připojena posloupnost bitových 0, 
   kde je jejich počet dán vzorcem `(448 - l_bits - 1) % 512`, kde l_bits je velikost vstupního textu v bitech a následně 
   je za ně připojena 8bytová část v big endian formátu obsahující velikost vstupního textu v bitech.
3. **Hlavní smyčka:** Hlavní smyčka algoritmu iterativně aplikuje postupně na každý blok algoritmus SHA-256, kde iniciální 
   hash následujícího bloku je dán hashem předcházejícího bloku vyjma prvního bloku, kde je iniciální hash dán standardem. 
4. **Finální hash:** Po zpracování všech bloků vstupního textu algoritmus vrací finální hash hodnotu.

### MAC (Message Authentication Code)
Implementace generování MAC vychází ze vzorce `MAC = SHA256(SECRET_KEY + MSG)` a to konkrétně následovně: 

1. **Tajný klíč + vstupní textu**: Po řadě je za sebe připojen tajný klíč a vstupní text.
2. **Výpočet hash**: Na spojený řetězec tajného klíče a vstupního textu je aplikována funkce SHA-256.
3. **Výsledek**: Výsledkem aplikace této funkce nad daným řetězcem s tajným klíčem je MAC.

### Ověření MAC
Implementace ověření MAC funguje následovně:

1. **Generování MAC**: Je vygenerován MAC dle popisu generování MAC výše.
2. **Porovnání**: Vygenerovaný MAC se porovná s dodaným MAC a pokud se oba MAC shodují, tak daný hash byl vygenerovaný pomocí tajného klíče.

### Length extension attack
Tento útok využívá vlastnosti některých hashovací algoritmů, jako je SHA-256, kde tyto algoritmy umožňují vypočítat 
validní MAC, kde je původní zpráva rozšířena o určitý text, bez znalosti tajného klíče (je potřeba znát pouze jeho délku). 
Implementace tohoto typu útoku má je založena na [2,3,4,5] a má následující princip: 

1. **Výchozí stav**: Na začátku výpočtu je třeba znát původní zprávu, MAC této zprávy a délku klíče.
2. **Rozšíření zprávy**: Za prázdné místo o velikosti klíče se připojí původní text a následně se vypočítá padding, pokud 
   je potřeba. Za takto vytvořený blok se připojí si rozšířený text (útočníkův text) a následně se opět přidá padding pokud je potřeba.
3. **Výpočet MAC**: Nad tímto vytvořeným blokem se aplikuje hashovací funkce SHA-256, která bude mít místo iniciálních stavů hashe 
   uložen hash původní zprávy.

Princip útoku využívá toho, že daný algoritmus zpracovává data po blocích a uchovává si mezivýpočty mezi jednotlivými 
bloky (poslední mezivýpočet je výsledný hash). Je tedy možné použít známý hash jako výchozí bod pro výpočet hash pro 
jakoukoli přidanou zprávu. Jinými slovy je možné díky znalosti původní zprávy, MAC této zprávy a délky tajného klíče 
pokračovat ve výpočtu následujícího bloku (bloku s přidaným textem) i bez znalosti tajného klíče. 

## Spuštění
* **-c:** Výpočet hashe vstupní zprávy.
* **-s -k \<klic\>:** Generování MAC (Message Authentication Code) ze vstupní zprávy a tajného klíče.
* **-v -k \<klic\> -m \<mac\>:** Ověření MAC pro vstupní zprávu a tajný klíč.
* **-e -n \<delka_klice\> -a \<pridany_text\> -m \<mac\>:** Aplikace length extension attacku.

## Příklady vstupů a výstupů
* Výpočet SHA-256 
```[bash]
$ echo -ne "zprava" | ./kry -c
d8305a064cd0f827df85ae5a7732bf25d578b746b8434871704e98cde3208ddf
```
* Generování MAC
```[bash]
$ echo -ne "zprava" | ./kry -s -k heslo
23158796a45a9392951d9a72dffd6a539b14a07832390b937b94a80ddb6dc18e
```
* Ověření MAC
```[bash]
$ echo -ne "zprava" | ./kry -v -k heslo -m 23158796a45a9392951d9a72dffd6a539b14a07832390b937b94a80ddb6dc18e
$ echo $?
0
```
* Length Extension Attack
```[bash]
$echo -ne "zprava" | ./kry -e -n 5 -a ==message -m 23158796a45a9392951d9a72dffd6a539b14a07832390b937b94a80ddb6dc18e
a3b205a7ebb070c26910e1028322e99b35e846d5db399aae295082ddecf3edd3zprava\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x58==message
```


## Zdroje

Zdroj pro implementaci hashovacího algoritmu sha256:
* [1] http://dx.doi.org/10.6028/NIST.FIPS.180-4

Zdroje pro pochopení length extension attacku:
* [2] https://lord.io/length-extension-attacks/
* [3] https://bostik.iki.fi/dc4420/size_t-does-matter--hash-length-extensions.pdf
* [4] https://www.javacodegeeks.com/2012/07/hash-length-extension-attacks.html
* [5] https://github.com/viensea1106/hash-length-extension