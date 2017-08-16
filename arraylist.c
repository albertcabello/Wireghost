#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/slab.h>
#include "arraylist.h"

void arraylist_initial(struct arraylist *list) {
    list->size = 0;
    list->data = NULL;
}

int arraylist_get_size(const struct arraylist list) {
    return list.size;
}

value_type* arraylist_get_data_collection(const struct arraylist list) {
    return list.data;
}

void arraylist_set_data_collection(struct arraylist *list, value_type* data) {
    list->data = data;
}

void arraylist_add(struct arraylist *list, value_type value) {
    int size = arraylist_get_size(*list);
    value_type *new_data;
    
    new_data = krealloc(list->data, (size + 1) * sizeof new_data[0],GFP_KERNEL);
    
    if (new_data)
    {
        new_data[size] = value;
        arraylist_set_data_collection(list, new_data);
        ++list->size;
    }
}

value_type arraylist_get(const struct arraylist list, int index) {
    if(index < arraylist_get_size(list)) {
        return list.data[index];
    }
    else {
        return -1;
    }
}
//returns number of appearances
int arraylist_contains(const struct arraylist list, value_type value) {
    int index = 0;
    int counter = 0;
    for(; index != arraylist_get_size(list); ++index) {
        if(list.data[index]==value) {
            counter++;
        }
    }
    
    return counter;
}

int arraylist_first(const struct arraylist list, value_type value) {
    int index = 0;
    for(; index != arraylist_get_size(list); ++index) {
        if(list.data[index]==value){
            return index;
        }
    }
    
    return -1;
}


void initArray(Array *a, int initialSize) {
    a->array = (int *)kmalloc(initialSize * sizeof(int),GFP_KERNEL);
    a->used = 0;
    a->size = initialSize;
}

void insertArray(Array *a, int element) {
    // a->used is the number of used entries, because a->array[a->used++] updates a->used only *after* the array has been accessed.
    // Therefore a->used can go up to a->size
    if (a->used == a->size) {
        a->size *= 2;
        a->array = (int *)krealloc(a->array, a->size * sizeof(int),GFP_KERNEL);
    }
    a->array[a->used++] = element;
}
//returns 1 if true and -1 if false
int contains(Array *a, int element){
    int i = 0;
    for (;i<a->size;i++){
        if (a->array[i] == element){
            return 1;
        }
    }
    return -1;
}
int size(Array *a){
    return a->size;
}
int getArray(Array *a, int index){
    return a->array[index];
}
void freeArray(Array *a) {
    kfree(a->array);
    a->array = NULL;
    a->used = a->size = 0;
}
void updateArray(Array *a, int index, int newValue){
    a->array[index]=newValue;
}




