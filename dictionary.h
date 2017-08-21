#ifndef DICTIONARY_H
#define DICTIONARY_H

/* Preferably keep this a prime number
 * since my hash function isn't great */
#define HASH_TABLE_SIZE 101

//Structure to store the entries in the table
//Is a linked list
typedef struct entry entry;
struct entry {
	struct entry *next;
	int ip;
	int offset;
};

//Sequence and acknowledgement number tables
extern entry* seqTable[HASH_TABLE_SIZE];
extern entry* ackTable[HASH_TABLE_SIZE];

extern entry* storeVal(struct entry **table, struct entry add);
extern entry* getVal(struct entry **table, int ip);
#endif 
