#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <math.h>
#include <sys/types.h> 
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <linux/sockios.h>
#include <netdb.h>
#include <pthread.h>
#include <openssl/aes.h>
#include <openssl/rand.h>

#include "common_def.h"

#define STDIN 0
#define STDOUT 1
#define MAX(x, y) (((x) > (y)) ? (x) : (y))

void request_handler(int);
void encrypt_decrypt(char *, char *, unsigned char[], int);
char *get_key(char *);
AES_KEY aes_key;
ctr_state state;
arg_t *arguments;
struct hostent *server;
fd_set readfds;

int main(int argc, char *argv[]) {

	int rc,option, sockfd, newsockfd, clilen, n;
	unsigned int lflag = 0, kflag = 0, hflag = 0;
	char usage[] = "Usage: pbproxy [-l port] -k keyfile destination port \n";
	char optstring[] = "hl:k:";
	char buffer[9192];
	char *key;
	struct sockaddr_in serv_addr, client_addr;
	int pid;
	size_t i;
	unsigned char IV_sent[8], IV_recv[8];
	char *encrypted_data, *decrypted_data, *data_sent, *data_recv;

	arguments = (arg_t *)malloc(sizeof(arg_t));

	/* Intializing arguments to their default value */
	arguments->keyfile = (char *) malloc(sizeof (char *));	
	strcpy(arguments->keyfile, " ");
	(*arguments).in_port = 0;
	arguments->dest = (char *) malloc(sizeof (char *));	
	strcpy(arguments->dest, "localhost");
	(*arguments).dest_port = 22;


	while((option = getopt(argc, argv, optstring)) != (-1)) {
		switch(option) {
			
			case 'l':
				lflag++;
				(*arguments).in_port = atoi(optarg);
				break;
			
			case 'k':
				kflag++;
				arguments->keyfile = optarg;
				break;
			case 'h':
				hflag++;
				printf("%s", usage);
				break;
	
			case '?':		
				fprintf(stderr, "Invalid Character %c found\n For help use -h\n", optopt);
				exit(-1);
				break;
		}
	}
	if (hflag == 1) {
		/* Usage is already printed. Exit now. */
		exit(-1);
	}
	if (kflag != 1) {
		if ((hflag == 1 && kflag != 0) || (hflag == 0)) {
			fprintf(stderr, "Invalid Option in argument. Use -h for more help of command usage.\n");
			exit(-1);
		}
	}

	if(optind < argc && optind+2 == argc) {
		arguments->dest  = argv[optind];
		optind++;
		(*arguments).dest_port = atoi(argv[optind]);
	}	
	else {
		fprintf(stderr, "Error in command usage. Usage is %s\n", usage);
		exit(-1);
	}

	sockfd = socket(AF_INET, SOCK_STREAM, 0);	
    if (sockfd < 0) {
       	fprintf(stderr, "Error opening socket\n");
		exit(-1);		
	}

	/* Get key from file, exit if not found. */
	key = get_key(arguments->keyfile);
	if (key == NULL) {
		exit(-1);
	}

	/*Set encryption key */
	if (AES_set_encrypt_key(key, 128, &aes_key) < 0) {
        fprintf(stderr, "Could not set encryption key. Disconnecting...\n");
        exit(-1); 
    }

	// Everything is validated at this point and now need to decide if this is server or client
	if (lflag == 1) {
		/* This code is for server proxy*/
	    bzero((char *) &serv_addr, sizeof(serv_addr));

	    serv_addr.sin_family = AF_INET;
	    serv_addr.sin_addr.s_addr = INADDR_ANY;
	    serv_addr.sin_port = htons((*arguments).in_port);
	    if (bind(sockfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0) {
			fprintf(stderr, "Error in binding socket\n");	
			exit(-1);
		}
		listen(sockfd, 5);

		while(1) { 	   		
			newsockfd = accept(sockfd, (struct sockaddr *) &client_addr, &clilen);
			if (newsockfd < 0) {
		        fprintf(stderr, "Error on accept\n");
				exit(-1);
			}
     		pid = fork();
     		if (pid < 0) {
         		fprintf(stderr, "Error on fork\n");
				exit(-1);
			}
     		if (pid == 0)  {
         		close(sockfd);
				request_handler(newsockfd);
         		exit(0);
     		} else
				close(newsockfd);
		}
	} else {
		/*This code is for client proxy*/
		server = gethostbyname(arguments->dest);
		if (server == NULL) {
	        fprintf(stderr, "Error. No such host. Connection is terminated!\n");
	        exit(-1);
	    }

		bzero((char *) &serv_addr, sizeof(serv_addr));
	    serv_addr.sin_family = AF_INET;
	    bcopy(server->h_addr, (char *)&serv_addr.sin_addr.s_addr, (*server).h_length);
	    serv_addr.sin_port = htons((*arguments).dest_port);
    	if (connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
    	    printf("Error in connecting to server proxy. Disconnected!\n");
			exit(-1);
		}

		while (1) {
			FD_ZERO(&readfds);
			FD_SET(STDIN, &readfds);
			FD_SET(sockfd, &readfds);
			select(sockfd+1, &readfds, NULL, NULL, NULL);

			if (FD_ISSET(STDIN, &readfds)) {
	    		bzero(buffer, 9192);
				n = read(STDIN, buffer, 9192);
				if (n <= 0) {
					fprintf(stderr, "Connection is terminated!\n");
					close(sockfd);
					break;
				}
				if(!RAND_bytes(IV_sent, AES_BLOCK_SIZE)) {
        			fprintf(stderr, "Could not create random bytes. Disconnected!\n");
       				close(sockfd);
					break;
	 			}
				encrypted_data = (char *) calloc(n, sizeof(char));
				encrypt_decrypt(buffer, encrypted_data, IV_sent, n);
				data_sent = (char *) calloc(n+8+1, sizeof(char));
				memcpy(data_sent, IV_sent, 8);
				memcpy(data_sent+8, encrypted_data, n);
				n = write(sockfd, data_sent, n+8);
	    		if (n <= 0) {
       				fprintf(stderr, "Connection is terminated!\n");
					close(sockfd);
					break;
				}
				free(encrypted_data);
				free(data_sent);
			} else if (FD_ISSET(sockfd, &readfds)) {
				bzero(buffer, 9192);
				data_recv = (char *) calloc(sizeof(buffer)+8, sizeof(char));
				n = read(sockfd, data_recv, sizeof(buffer)+8);
				if (n <= 0) {
					fprintf(stderr, "Connection is terminated!\n");
					close(sockfd);
					exit(-1);
				}
				memcpy(IV_recv, data_recv, 8);
				memcpy(buffer, data_recv+8, n-8);
				decrypted_data = (char *) calloc(n-8, sizeof(char));
				encrypt_decrypt(buffer, decrypted_data, IV_recv, n-8);
				n = write(STDOUT, decrypted_data, n-8);
				if (n <= 0) {
					fprintf(stderr, "Connection is terminated!\n");
					close(sockfd);
					break;
				}
				free(decrypted_data);
				free(data_recv);
			}
		}
	}	
	return 0;
}

/**
* request_handler
* @sockfd: This is a descriptor associated with the client proxy
*
* This function is for handling each client connection on server side. It initiate connection with SSH and
* redirects traffic from client to ssh remote host.
*
**/
void request_handler(int sockfd) {
	char buffer[9192];
	size_t i;	
	int n, ssh_sock, l;
	char *encrypted_data, *decrypted_data, *data_sent, *data_recv;
	struct sockaddr_in sshsock_addr;
	unsigned char IV_sent[8], IV_recv[8];

	bzero(&sshsock_addr, sizeof(sshsock_addr));
	ssh_sock = socket(AF_INET, SOCK_STREAM, 0);
	if (ssh_sock < 0) {
		fprintf(stderr, "Unable to create ssh socket. Disconnecting...\n");
		exit(-1);
	}
	server = gethostbyname(arguments->dest);
	if (server == NULL) {
        fprintf(stderr, "Error. No such host. Disconnecting...\n");
        exit(-1);
    }
	sshsock_addr.sin_family = AF_INET;
	sshsock_addr.sin_port = htons((*arguments).dest_port);
	bcopy(server->h_addr, (char *)&sshsock_addr.sin_addr.s_addr, (*server).h_length);

	if (connect(ssh_sock, (struct sockaddr *)&sshsock_addr, sizeof(sshsock_addr)) == -1) {
		fprintf(stderr, "Connection to ssh failed! Disconnected!\n");
		close(sockfd);
		exit(-1);
	}

	while (1) {
		FD_ZERO(&readfds);
		FD_SET(ssh_sock, &readfds);
		FD_SET(sockfd, &readfds);
		select(MAX(ssh_sock, sockfd)+1, &readfds, NULL, NULL, NULL);
		
		if (FD_ISSET(sockfd, &readfds)) {
			bzero(buffer, 9192);
			data_recv = (char *) calloc(sizeof(buffer)+8, sizeof(char));
			n = read(sockfd, data_recv, sizeof(buffer)+8);
			if (n <= 0) {
				fprintf(stderr, "Connection is terminated!\n");
				close(sockfd);
				close(ssh_sock);
				break;
			}
			memcpy(IV_recv, data_recv, 8);
			memcpy(buffer, data_recv+8, n-8);
			decrypted_data = (char *) calloc(n-8, sizeof(char));
			encrypt_decrypt(buffer, decrypted_data, IV_recv, n-8);
			n = write(ssh_sock, decrypted_data, n-8);
			if (n <= 0) {
				fprintf(stderr, "Connection is terminated!\n");
				close(sockfd);
				close(ssh_sock);
				break;
			}
			free(decrypted_data);
			free(data_recv);
		} else if (FD_ISSET(ssh_sock, &readfds)) {
			ioctl(sockfd, SIOCOUTQ, &l);
			if (l > 0)
				continue;
			
			bzero(buffer, 9192);
			n = read(ssh_sock, buffer, sizeof(buffer));
			if (n <= 0) {
				fprintf(stderr, "Connection is terminated!\n");
				close(ssh_sock);
				close(sockfd);
				break;
			}
			if(!RAND_bytes(IV_sent, AES_BLOCK_SIZE)) {
        		fprintf(stderr, "Could not create random bytes for IV. Disconnecting...\n");
       			close(sockfd);
				close(ssh_sock);
				break;
	 		}
			encrypted_data = (char *) calloc(n, sizeof(char));
			encrypt_decrypt(buffer, encrypted_data, IV_sent, n);
			data_sent = (char *) calloc(n+8+1, sizeof(char));
			memcpy(data_sent, IV_sent, 8);
			memcpy(data_sent+8, encrypted_data, n);

			n = write(sockfd, data_sent, n+8);
	    	if (n <= 0) {
       			fprintf(stderr, "Connection is terminated!\n");
				close(sockfd);
				break;
			}
			free(encrypted_data);
			free(data_sent);
		}
	}
}

/**
* encrypt_decrypt
* @text: This is a pointer to text on which encryption/decryption operation is performed
* @enc_dec_data: This will contain encrypted/decrypted data
* @IV: This is a Initialization verctor used for encryption/decryption
* @size: This is number of characters to encrypted/decrypt.
*
* This is a generic function which will do encryption/decryption of given text and store it
* in other text. Different IV is passed for every encryption/decryption operation.
*
**/
void encrypt_decrypt(char *text, char *enc_dec_data, unsigned char IV[], int size) {
    (&state)->num = 0;
    memset((&state)->ecount, 0, AES_BLOCK_SIZE);
    memset((&state)->ivec + 8, 0, 8);
    memcpy((&state)->ivec, IV, 8);

	AES_ctr128_encrypt(text, enc_dec_data, size, &aes_key, state.ivec, state.ecount, &state.num);
}

/**
* get_key
* @filename: This is a pointer to filename which contains symmetric key for encryption/decryption operation
*
* This function is used to read symmetric key from file.
*
* This function returns pointer to symmetric key which is read from file or returns NULL if file is not found
* or user have not permission to read it.
**/
char *get_key(char *filename) {
	char *keybuf;
	long length;
	size_t i;
	// Reading file in binary format so "b" in mode
	FILE *fp = fopen(filename, "rb");
	if (fp) {
		fseek(fp, 0, SEEK_END);
		length = ftell(fp);
		fseek(fp, 0, SEEK_SET);
		keybuf = (char *)malloc(length);
		if (keybuf)
			fread(keybuf, 1, length, fp);
		fclose(fp);
	} else {
		fprintf(stderr, "Unable to open file for reading key. Check for keyfile.\n");
		return NULL;
	}
	return keybuf;
}
