# Diffie-Hellman
An implementation of the Diffie-Hellman shared secret generation algorithm in C.

It uses integer arrays so you can theoretically use numbers as large as you'd like, but in my test case it's just 256 bit with the standard 2048 bit prime.

It also uses openssl so remember to include lcrypto (gcc -o out main.c dh.c -lcrypto).
