# Základní obraz
FROM ubuntu:jammy

# Instalace potřebných nástrojů (GCC, Make)
RUN apt-get update && apt-get install -y \
    gcc \
    make \
    && rm -rf /var/lib/apt/lists/*

# Kopírování vašeho projektu do kontejneru
COPY . /KRY-project2

# Nastavení pracovního adresáře
WORKDIR /KRY-project2

# Kompilace vašeho projektu
RUN make all

# Spuštění aplikace při startu kontejneru
CMD ["chmod u+x sha256test.sh"]
CMD ["./sha256test.sh"]
