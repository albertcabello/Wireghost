#include "dictionary.h"
#include<stdlib.h>
#include<stdio.h>

static entry *seqTable[13];
unsigned int hash(int ip) {
	return ip * 31 % HASH_TABLE_SIZE;
}
/* stores an entry in the given table
 * returns a pointer to the new entry */
entry* storeVal(struct entry *table[], entry add) {
	int index = hash(add.ip); //Hash the ip
	entry *try;
	try = table[index];
	while (try) {
		if (try->ip == add.ip) {
			return try;
		}
		try = (try->next);
	}
	try = malloc(sizeof(entry));
	try = &add;
	printf("Stored in index %d\n", index);
	return try;
}

/* gets the entry for the given IP address 
 * if the entry doesn't exist, returns NULL */
entry* getVal(struct entry *table[], int ip) {
	int index = hash(ip); //Hash the ip
	entry *try; //Iterator for linked list
	while (try) {
		if (try->ip == ip) {
			return try;
		}
		try = try->next;
	}
	//If we got here, there is no entry
	return NULL;
}
/* Adds to the offset of a given entry
 * to it's matching entry 
 * Saves entry calls from having to do getVal(table, entry)->offset += offset */
entry* addVal(struct entry *table[], entry add) {
	/* Get location of the entry to add to */
	entry * t = getVal(table, add.ip);
	/* If that entry doesn't exist, return NULL */
	if (t == NULL) {
		return NULL;
	}
	/* Add the offset to the entry */
	t->offset += add.offset;
	/* Return the entry */
	return t;
}
/* Update an entry with an entirely new offset
 * The updated entry CANNOT have a new IP */
entry* updateVal(struct entry *table[], entry update) {
	/* Get the entry to update */
	entry * t = getVal(table, update.ip);
	/* If it's null, return NULL */
	if (t == NULL) {
		return NULL;
	}
	/* change pointer to the new entry */
	t = &update;
	return t;
}
int main() {
	entry t;
	t.ip = 1;
	t.offset = 1;
	storeVal(seqTable, t);
	t.ip = 27;
	t.offset = 2;
	storeVal(seqTable, t);
	t.ip = 3;
	t.offset = 3; 
	storeVal(seqTable, t);
	t.ip = 1;
	t.offset = 3;
	/*
	printf("The offset for ip 27: %d\n", getVal(seqTable, 27)->offset);
	printf("The new offset for ip 1: %d\n", addVal(seqTable, t)->offset);
	t.ip = 3;
	t.offset = 15;
	printf("The new offset for ip 3: %d\n", updateVal(seqTable, t)->offset);
	*/
	return 0;
}
