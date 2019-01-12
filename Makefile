aes: aes.c
	gcc -o aes aes.c -Wall -std=c99
	
clean:
	rm aes