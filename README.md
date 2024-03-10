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

### MAC (Message Authentication Code)

### Ověření MAC

### Length extension attack

## Spuštění
* **-c:** Vypočet hashe vstupní zprávy.
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