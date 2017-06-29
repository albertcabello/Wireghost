#include<stdio.h>
#include<string.h>

void payloadFind(const char* payload, const char* key, const char* replacement) {
	//Location of the key
	char *loc;
	//If the key is not in the payload, just return the payload
	if (!(loc=strstr(payload, key))) return;
	//Temporary array to hold the string after replacement, needs to be long enough to contain the entire new string
	//So the original string minus what you're replacing plus the replacement length is exactly long enough
	char temp[strlen(payload)-strlen(key)+strlen(replacement)];
	//Add null character to prevent garbage characters
	temp[loc-payload] = '\0';
	//Copy payload up to substring
	strncpy(temp, payload, loc-payload);
	//Concatenate the replacement string
	strcat(temp, replacement);
	//Reassign payload
	payload = temp;
	printf("%s", payload);
}	


int main() {
	payloadFind("abcd", "abcd", "efghijk");
	return 0;
}
