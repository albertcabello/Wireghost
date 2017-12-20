#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<errno.h>
#include<unistd.h>
#include<sys/socket.h>
#include<linux/netlink.h>
#define BITECOIN 17
#define MAX_PAYLOAD 1024
int main() {
	char *input, *command, *firstarg, *secondarg, *msgToSend;
	size_t maxInputLen = MAX_PAYLOAD;
	size_t trailingNewline;
	int inputTaken = 0;
	input = malloc(1024);
	int fd = socket(PF_NETLINK, SOCK_RAW, BITECOIN); //Doesn't work unless kernel module is running
	if (fd < 0) {
		printf("No one listening on Wireghost's netlink, make sure it's inserted\n");
		return -1;
	}
	//Source socket to receive messages from kernel
	struct sockaddr_nl nladdr = {
		.nl_family	= AF_NETLINK,
		.nl_pad 	= 0,
		.nl_pid 	= getpid(),
		.nl_groups	= 0
	};
	bind(fd, (struct sockaddr *)&nladdr, sizeof(nladdr));
	//Destination socket to send messages to the kernel
	struct sockaddr_nl d_nladdr = {
		.nl_family 	= AF_NETLINK,
		.nl_pad 	= 0,
		.nl_pid 	= 0, //PID of 0 is kernel
		.nl_groups	= 0
	};
	//Set netlink message header for sending 
	struct nlmsghdr *nlh = NULL;
	nlh = (struct nlmsghdr *)malloc(NLMSG_SPACE(MAX_PAYLOAD));
	strcpy(NLMSG_DATA(nlh), "Ayyyyeee kernel how you doin?");
	nlh->nlmsg_len = NLMSG_SPACE(MAX_PAYLOAD);
	nlh->nlmsg_pid = getpid();
	nlh->nlmsg_flags = 1;
	nlh->nlmsg_type = 0;


	//IOV structure for sending
	struct iovec iov = {
		.iov_base 	= (void *)nlh,
		.iov_len 	= nlh->nlmsg_len
	};

	//Message header for sending
	struct msghdr msg = {
		.msg_name 	= (void *)&d_nladdr,
		.msg_namelen	= sizeof(d_nladdr),
		.msg_iov 	= &iov,
		.msg_iovlen 	= 1
	};

	//Send out the message
//	printf("Sending kernel message\n");
//	sendmsg(fd, &msg, 0);

	//Receive kernel message
//	memset(nlh, 0, NLMSG_SPACE(MAX_PAYLOAD));
//	recvmsg(fd, &msg, 0);
//	printf("Received message from kernel %s\n", (char *)NLMSG_DATA(nlh));

	for(;;) {
		msgToSend = malloc(MAX_PAYLOAD);
		/* This is actually really cool
		 * Store the user input in a variable and to prevent it from including the new line
		 * make getline the argument to the indexing of the input variable and subtract line
		 */
		command = malloc(MAX_PAYLOAD);
		firstarg = malloc(MAX_PAYLOAD);
		secondarg = malloc(MAX_PAYLOAD);
		while (!inputTaken) {
			printf("What would you like to do (inject/mangle/clear)?\n");
			input[getline(&input, &maxInputLen, stdin) - 1] = '\0';
			//Injection if statement
			if (!strcmp(input, "inject") || !strcmp(input, "i") || !strcmp(input, "I")) {
				strcpy(command, "i");
				printf("What would you like to inject?\n");
				input[getline(&input, &maxInputLen, stdin) - 1] = '\0';
				strcpy(firstarg, input);
				sprintf(msgToSend, "%s:%s", command, firstarg);
				inputTaken = 1;
			}
			//Mangle if statement
			else if (!strcmp(input, "mangle") || !strcmp(input, "m") || !strcmp(input, "M")) {
				strcpy(command, "m");
				printf("What would you like to mangle?\n");
				input[getline(&input, &maxInputLen, stdin) - 1] = '\0';
				strcpy(firstarg, input);
				printf("What will be the result of the mangle?\n");
				input[getline(&input, &maxInputLen, stdin) - 1] = '\0';
				strcpy(secondarg, input);
				sprintf(msgToSend, "%s:%s:%s", command, firstarg, secondarg);
				inputTaken = 1;
			}
			else if (!strcmp(input, "clear") || !strcmp(input, "c") || !strcmp(input, "C")) {
				strcpy(command, "c");
				printf("Would you like to clear the mangle dictionary or the injection stack?\n");
				input[getline(&input, &maxInputLen, stdin)-1] = '\0';
				strcpy(firstarg, input);
				sprintf(msgToSend, "%s:%s", command, firstarg);
				inputTaken = 1;
			}
			else {
				printf("Invalid input, please pick a command.  Either inject or mangle\n");
			}
		}
		inputTaken = 0;
		//There needs to be a better way to send messages that doesn't involve 
		// reinstantiating nlh
		memset(nlh, 0, NLMSG_SPACE(MAX_PAYLOAD));
		strcpy(NLMSG_DATA(nlh), msgToSend);
		nlh->nlmsg_len = NLMSG_SPACE(MAX_PAYLOAD);
		nlh->nlmsg_pid = getpid();
		nlh->nlmsg_flags = 1;
		nlh->nlmsg_type = 0;
		//Send off command
		sendmsg(fd, &msg, 0);
		
		//Receive kernel confirmation
		recvmsg(fd, &msg, 0);
		printf("Kernel response: %s", (char *)NLMSG_DATA(nlh));
		free(command);
		free(msgToSend);
		free(firstarg);
		free(secondarg);
	}

	//Close socket
	close(fd);

	return 0;
}
/*
 * This is Bitecoin (no longer JavaScript).  How does it work?  
 * Wireghost is now equipped with a socket server that can communicate
 * with the userspace.  No more iptables and dummy packets to communicate
 * with Wireghost!  Now you can tell Wireghost to queue up injection packets and
 * add new mangle rules in real time.
 */
