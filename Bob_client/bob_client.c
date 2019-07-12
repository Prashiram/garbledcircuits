#include<stdio.h>
#include<stdlib.h>
#include<sys/types.h>
#include<sys/socket.h>
#include <arpa/inet.h>
#include <strings.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h> /* for pid_t */
#include <sys/wait.h> /* for wait */
#include<netinet/in.h>
#define BUFFER_SIZE 350

int main(int argc, char** argv)
{
	int alice, bob;
	FILE *ciph, *keys, *initvec, *hash, *al_input, *c_out, *enc_messages, *random, *message;

	//Creating socket Alice
	alice = socket(AF_INET, SOCK_STREAM, 0);

	//Setting necessary values for the server (ip address and port no. are received as command line arguments)
	struct sockaddr_in server_alice;
	server_alice.sin_family=AF_INET;
	server_alice.sin_port=htons(atoi(argv[2]));
	server_alice.sin_addr.s_addr=inet_addr(argv[1]);
	bzero(&server_alice.sin_zero, 8);

	//Connecting to Alice
	if(connect(alice, (struct sockaddr*)&server_alice, sizeof(struct sockaddr_in)) == -1){
		printf("Connection could not be established!");
		exit(-1);
	}

	printf("Connection to Alice successful\n");

	
	//Buffer of length BUFFER_SIZE is used to send and recieve messages
	char *buffer;
	buffer = (char*)malloc(BUFFER_SIZE*sizeof(char));
	
	/****************/
	initvec = fopen("initvec.txt", "w");

	printf("Receiving iv from Alice...\n");
	recv(alice, buffer, BUFFER_SIZE, 0);    //A0
	fprintf(initvec, "%s\n", buffer);
	bzero(buffer, strlen(buffer));
	printf("iv received....\n");
	fclose(initvec);

	/*****************/
	printf("Receiving garbled table from Alice...\n");

	//Receive garbled table generated by alice_gate to Bob

	/************************Receiving the GARBLED TABLE********************************/	
	
	ciph = fopen("ciph.txt", "w");

	recv(alice, buffer, BUFFER_SIZE, 0);    //A1
	fprintf(ciph, "%s\n", buffer);
	bzero(buffer, strlen(buffer));

	recv(alice, buffer, BUFFER_SIZE, 0);    //A2
	fprintf(ciph, "%s\n", buffer);
	bzero(buffer, strlen(buffer));

	recv(alice, buffer, BUFFER_SIZE, 0);    //A3
	fprintf(ciph, "%s\n", buffer);
	bzero(buffer, strlen(buffer));

	recv(alice, buffer, BUFFER_SIZE, 0);    //A4
	fprintf(ciph, "%s\n", buffer);
	bzero(buffer, strlen(buffer));

	fclose(ciph);

	printf("Garbled table has been received from Alice!\n");

	


	/*********************************Receiving hashes**********************************/
	
	printf("Now receiving the hashes of the encrypted outputs...\n");

	hash = fopen("hash.txt", "w");

	recv(alice, buffer, BUFFER_SIZE, 0);    //A5
	fprintf(hash, "%s\n", buffer);
	bzero(buffer, strlen(buffer));

	recv(alice, buffer, BUFFER_SIZE, 0);    //A6
	fprintf(hash, "%s\n", buffer);
	bzero(buffer, strlen(buffer));

	fclose(hash);

	printf("Hashes received....\n");


	/****************************Receiving Alice's input label********************************/
	
	al_input = fopen("al_input.txt", "w");

	recv(alice, buffer, BUFFER_SIZE, 0);    //A7
	fprintf(al_input, "%s\n", buffer);
	bzero(buffer, strlen(buffer));

	fclose(al_input);


	/***********************************Oblivious Transfer for receiving b0/b1*******************************************/
	

	//text file that stores the random numbers generatd by alice
	random = fopen("randomx.txt", "w");

	//Recieves the random strings from alice and writes to text file
	recv(alice, buffer, BUFFER_SIZE, 0);    //A8
	fprintf(random,"%s\n",buffer);
	bzero(buffer, strlen(buffer));
	recv(alice, buffer, BUFFER_SIZE, 0);    //A9
	fprintf(random,"%s",buffer);
	bzero(buffer, strlen(buffer));

	fclose(random);
	printf("Randomly generated strings recieved from ALice\n");

	
	//Fork to execute bob1
	pid_t pid=fork();

	//child process
	if(pid==0)
	{
		//Execute bob1
		static char *argv[]={"bob1",NULL};
		execv("bob1", argv);
		exit(-1);
	}

	//Waits for child process to finish
	wait(NULL);

	//text file that contains the c generated by bob
	c_out = fopen("bob_c.txt", "r");

	//Sends the c generated by bob1 to alice
	fscanf(c_out, "%s", buffer);
	send(alice, buffer, BUFFER_SIZE, 0);    //B1
	bzero(buffer, strlen(buffer));
	
	fclose(c_out);
	printf("c sent to ALice\n");

	
	//text file that stores encrypted messages
	enc_messages = fopen("enc_messages.txt", "w");

	//receives the encrypted messages generated by Alice and stores in text file
	recv(alice, buffer, BUFFER_SIZE, 0);    //A10
	fprintf(enc_messages,"%s\n",buffer);
	bzero(buffer, strlen(buffer));
	recv(alice, buffer, BUFFER_SIZE, 0);    //A11
	fprintf(enc_messages,"%s",buffer);
	bzero(buffer, strlen(buffer));

	fclose(enc_messages);
	printf("Encrypted messages recieved from Alice\n");

	
	//Fork to execute bob2
	pid=fork();

	//child process
	if(pid==0)
	{
		//child process bob2
		static char *argv[]={"bob2",NULL};
		execv("bob2", argv);
		exit(-1);
	}

	//Waits for child process to finish
	wait(NULL);

	
	//close socket alice
	close(alice);
	printf("Transfer complete\n");

	
	//Display the recieved number stored in bob_message.txt
	message = fopen("bob_message.txt","r");
	fscanf(message,"%s", buffer);
	printf("Number recieved from Alice is: %s\n", buffer);

	//BOB GATE IS EXECUTED HERE FOR THE FINAL COMPUTATION
	//Fork to execute bob_gate
	pid=fork();
	
	//child process
	if(pid==0)
	{
		//child process bob_gate
		static char *argv[]={"bob_gate", NULL};
		execv("bob_gate", argv);
		exit(-1);
	}

	printf("bob gate has been executed\n");
}