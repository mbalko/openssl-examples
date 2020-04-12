CC = gcc
FLAGS = -Wall -pedantic

all: seal_open privkey.pem pubkey.pem

build: seal_open

seal_open: source.c
	$(CC) $(FLAGS) $^ -o $@ -lcrypto

privkey.pem:
	openssl genrsa -out $@ 2048

pubkey.pem:
	openssl rsa -in privkey.pem -pubout -out $@

example: privkey.pem pubkey.pem
	./seal_open -e examples/input.bmp pubkey.pem examples/encrypted
	./seal_open -d examples/encrypted privkey.pem examples/decrypted
	if [`diff examples/input.bmp examples/decrypted` -eq ""]; then echo ">> Decrypted successfuly - original file and decrypted file are identical."; fi

clean:
	rm -rf seal_open *.pem examples/*crypted
