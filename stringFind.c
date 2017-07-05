#include<stdio.h>
#include<string.h>
#include <stdlib.h>
int count = 0;
void payloadFind(const char* payload, const char* key, const char* replacement) {
	char * lastOccurence = (char *)payload;
	char * nextOccurence = strstr(payload, key);
	char temp[1500];
	int seen = 0;
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
	printf("%s", temp);
}	

int main() {
	payloadFind("abccdebc", "abccdebc", "ghzxxxx");
	return 0;
}

