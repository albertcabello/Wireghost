#ifndef DICTIONARY_H
#define DICTIONARY_H

//Preferably keep this a power of two
#define HASH_TABLE_SIZE 13

//Structure to store the entries in the table
//Is a linked list
typedef struct entry entry;
struct entry {
	struct entry *next;
	int ip;
	int offset;
};

extern entry * storeVal(struct entry *table[], struct entry add);
extern entry * getVal(struct entry *table[], int ip);
extern entry * addVal(struct entry *table[], struct entry add);
extern entry * updateVal(struct entry *table[], struct entry update);
#endif 
