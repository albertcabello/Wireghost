#include "dictionary.h"
#include<stdio.h>

unsigned int hash(__u32 ip) {
	return ip * 31 % HASH_TABLE_SIZE;
}
/* stores an entry in the given table
 * returns a pointer to the new entry */
entry* storeVal(struct entry *table[], struct entry add) {
	int index = hash(add.ip); //Hash the ip
	entry *t; //Entry to use for iteration
	/* Check if the specified index is not null */
	if (table[index]) { /* If null, loop through that bucket */
		t = table[index];
		/* Loop through the linked list as long as possible
		 * or until there's a duplicate */
		while (t->next & t->ip != add.ip) {
			t = t->next;
		}
		/* Make sure we didn't leave the while because of a 
		 * duplicate */
		if (t->ip == add.ip) {
			return t;
		}
		/* Append to the end of the linked list */
		t->next = malloc(sizeof(entry));
		t->next = add;
	}
	else { /* Not null, initialize bucket */
		table[index] = malloc(sizeof(entry));
		table[index] = &add;
	}
	/* Return pointer to new entry */
	return t; 
}

/* gets the entry for the given IP address 
 * if the entry doesn't exist, returns NULL */
entry* getVal(struct entry *table[], __u32 ip) {
	int index = hash(ip); //Hash the ip
	entry *t; //Iterator for linked list
	if (table[index]) { //If the bucket is occupied, loop through that list
		t = table[index];
		//If the head of the bucket is the right one, return it
		if (t->ip == ip) {
			return t;
		}
		//Else, loop through the list until the right one is found
		else {
			while (t->next) {
				if (t->ip == ip) {
					return t;
				}
				t = t->next;
			}
		}

	}
	//If we got here, there is no entry
	return NULL;
}
/* Adds to the offset of a given entry */
entry* addVal(struct entry *table[], struct entry add) {
	/* Get location of the entry to add to */
	entry * t = getVal(table[], add);
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
 * The updated entry CANNOT have a new IP
 * Saves entry calls from having to do getVal(table, entry)->offset += offset */
entry* updateVal(struct entry *table[], struct entry update) {
	/* Get the entry to update */
	entry * t = getVal(table[], add);
	/* If it's null, return NULL */
	if (t == NULL) {
		return NULL;
	}
	/* change pointer to the new entry */
	t = &update;
	return t;
}
