#include "dictionary.h"
#include<linux/slab.h>
#include<linux/module.h>

unsigned long hash(unsigned char *str) {
	unsigned long hash = 5381;
	int c;
	while (c = *str++) {
		hash = ((hash << 5) + hash) + c;
	}
	return hash % HASH_TABLE_SIZE;
}

/* Retrieves an entry for the given IP address
 * from the given table. Return NULL if not found
 * or a pointer to the entry if it was found */
entry * getVal(entry **table, unsigned char *ip) {
	entry * try;
	//Loop through linked list for bucket hash(ip);
	for (try = table[hash(ip)]; try != NULL; try = try->next) {
		/* If IP's are equal, return the entry */
		if (!strcmp(try->ip, ip)) {
			return try;
		}
	}
	/* Could not find the entry, return NULL */
	/* Because try was never assigned anything, it is still null, 
	 * but it points to its reference of null */
	return try;
}

/* Stores a given entry in the given table. 
 * Returns a pointer to the stored entry.
 * If an entry with the given IP address already
 * exists, that entry will be overridden with the new
 * given entry */
entry * storeVal(entry **table, entry val) {
	/* Find an entry for the ip */
	entry * try = getVal(table, val.ip);
	/* Entry where the hash of val is.
	 * this doesn't segfault because the end of
	 * the linked list is always NULL, so if this is
	 * NULL, it becomes the end of the linked list anyways */
	entry * origHash = table[hash(val.ip)];
	if (try == NULL) { //No existing entry
		/* Malloc try */
		try = kmalloc(sizeof(entry), GFP_KERNEL);
		if (try == NULL) { //Malloc failed
			return NULL;
		}
		/* Assign try to parameter */
		*try = val;
		/* try->next becomes the linked list
		 * and try is the head of it */
		try->next = origHash;
		/* Store linked list in the table */
		table[hash(val.ip)] = try;

	}
	else { //Found an existing entry
		/* Reassign entry */
		entry *next = try->next;
		*try = val;
		try->next = next;
	}
	/* Return entry */
	return try; 
}

/* If changes need to be made to the dictionary,
use this to test if it still works, at the end,
the ip of 72 should have offset 1000 and everything 
will have it's ip + 10 
*/

/*
int main() {
        int i = 0;
        for (i = 0; i < 100; i++) {
                entry t;
                t.ip = i;
                t.offset = i+10;
                storeVal(seqTable, t);
        }
        entry t;
        t.ip = 72;
        t.offset= 1000;
        storeVal(seqTable, t);
        for (i = 0; i < 10; i++) {
                entry *try;
                for (try = seqTable[i]; try != NULL; try = try->next) {
//                      If IP's are equal, return the entry
//                      if (try->ip == ip) {
//                              return try;
//                      }
                        printf("[IP: %d | Offset %d]->", try->ip, try->offset);
                }
                printf("NULL\n");
        }
        return 0;
} */
