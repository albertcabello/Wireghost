#include<stdio.h>
#include<string.h>
#include <stdlib.h>
int count = 0;
void payloadFind(char* payload, const char* key, const char* replacement) {
	char * lastOccurence; 
	char * nextOccurence; 	
	char * temp;
	int seen;
	temp = malloc(1500);
	seen = 0;
	nextOccurence = strstr(payload, key);
	lastOccurence = (char *)payload;
	while (nextOccurence != NULL) {
		seen++;
		count++;
//		temp = realloc(temp, strlen(payload)-seen*(strlen(key)+strlen(replacement)));
		strncat(temp, lastOccurence, nextOccurence-lastOccurence);
		strcat(temp, replacement);
		lastOccurence = nextOccurence+strlen(key);
		nextOccurence = strstr(nextOccurence+1, key);
	}
//	temp = realloc(temp, (strlen(payload)-seen*(strlen(key)+strlen(replacement))+strlen(lastOccurence)));
	strcat(temp, lastOccurence);
	payload = malloc(1500);
	strncpy(payload, temp, strlen(temp));
	printf("%s\n", payload);
}	

int main() {
	payloadFind("bcad", "a", "zyxw");
	return 0;
}

