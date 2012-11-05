
rm -rf dns_main;
gcc -Wall -O3 -g -I/usr/include/spf2/ -L/usr/include/spf2/ -lspf2 dns_pruebas.c -o dns_main -I/usr/include/spf2/ -L/usr/include/spf2/ -lspf2
