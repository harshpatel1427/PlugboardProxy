mydump: pbproxy.c
	gcc -o pbproxy pbproxy.c -lpthread -lcrypto
clean: 
	rm -rf pbproxy
