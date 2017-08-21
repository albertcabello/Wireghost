#include "dictionary.h"
#include<linux/slab.h>
#include<linux/module.h>

/* Hashes an IP address, not great but works */
unsigned int hash(int ip) {
	return ip * 31 % HASH_TABLE_SIZE;
}

/* Retrieves an entry for the given IP address
 * from the given table. Return NULL if not found
 * or a pointer to the entry if it was found */
entry * getVal(entry **table, int ip) {
	entry * try;
	//Loop through linked list for bucket hash(ip);
	for (try = table[hash(ip)]; try != NULL; try = try->next) {
		/* If IP's are equal, return the entry */
		if (try->ip == ip) {
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
		try = kmalloc(sizeof(entry), GFP_KERNEL);
		if (try == NULL) { //Malloc failed
			return NULL;
		}
		/* Assign try to parameter */
		*try = val;
		/* Start the linked list with try as only entry */
		table[hash(val.ip)] = try;
	}
	/* Return entry */
	return try; 
}

