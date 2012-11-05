/* 
 * File:   hsmap_main.c
 * Author: drordas
 *
 * Created on 28 de marzo de 2012, 10:11
 */

#include <stdio.h>
#include <stdlib.h>
#include "hashmap.h"

/*
 * 
 */
int print_elemen(any_t item, any_t data, any_t key){
    printf("KEY: %s\n",(char *)key);
    printf("ITEM: %d\n",*(int *)data);
    return MAP_OK;
}

int remove_elemen(any_t item, any_t data, any_t key){
    //printf("KEY: %s\n",(char *)key);
    //printf("ITEM: %d\n",*(int *)data);
    free(key);
    free(data);
    return MAP_OK;
}

int main(int argc, char** argv) {

    int *aux;
    char *string;
    int i;
    
    map_t map = hashmap_new();
    
    for(i=1;i<10;i++){
        string=malloc((sizeof(int)*2)+sizeof(char));
        sprintf(string,"%d",i);
        aux=malloc(sizeof(int));
        *aux=i;
        hashmap_put(map,string,aux);
    }
    
    hashmap_iterate_elements(map, &print_elemen,NULL);
    hashmap_iterate_elements(map, &remove_elemen,NULL);
    hashmap_free(map);
}

