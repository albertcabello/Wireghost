#ifndef DICTIONARY_H
#define DICTIONARY_H

//Preferably keep this a power of two
#define HASH_TABLE_SIZE 13

//Structure to store the entries in the table
//Is a linked list
struct entry {
	entry *next;
	__u32 ip;
	int offset;
};

extern entry * storeVal(struct entry *table[], struct entry add);
extern entry * getVal(struct entry *table[], __u32 ip);
extern entry * addVal(struct entry *table[], struct entry add);
extern entry * updateVal(struct entry *table[], struct entry update);
#endif 
