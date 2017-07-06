#ifndef _ARRAYLIST_H
#define _ARRAYLIST_H

#include <stdio.h>

typedef char* value_type;

struct arraylist {
    int size;
    value_type* data;
};
typedef struct {
    int *array;
    size_t used;
    size_t size;
} Array;
extern void initArray(Array *a, size_t initialSize);
extern void insertArray(Array *a, int element);
extern void freeArray(Array *a);
extern int contains(Array *a, int element);
extern size_t size(Array *a);
extern int getArray(Array *a, int index);
extern void updateArray(Array *a, int index, int newValue);
extern void arraylist_initial(struct arraylist *list);
extern int arraylist_get_size(const struct arraylist list);
extern value_type* arraylist_get_data_collection(const struct arraylist list);
extern void arraylist_set_data_collection(struct arraylist *list, value_type* data);
extern void arraylist_add(struct arraylist *list, value_type value);
extern value_type arraylist_get(const struct arraylist list, int index);
extern int arraylist_contains(const struct arraylist list, value_type value);
extern int arraylist_first(const struct arraylist list, value_type value);

#endif
