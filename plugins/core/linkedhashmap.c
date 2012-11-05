/****************************************************************
*
*   File    : linkedhashmap.c
*   Purpose : Implements a linkedhashmap library.
*
*
*   Author  : David Ruano Ordás
*
*
*   Date    : March  14, 2011
*
*****************************************************************************
*   LICENSING
*****************************************************************************
*
* WB4Spam: An ANSI C is an open source, highly extensible, high performance and
* multithread spam filtering platform. It takes concepts from SpamAssassin project
* improving distinct issues.
*
* Copyright (C) 2010, by Sing Research Group (http://sing.ei.uvigo.es)
*
* This file is part of WireBrush for Spam project.
*
* Wirebrush for Spam is free software; you can redistribute it and/or
* modify it under the terms of the GNU Lesser General Public License as
* published by the Free Software Foundation; either version 3 of the
* License, or (at your option) any later version.
*
* Wirebrush for Spam is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser
* General Public License for more details.
*
* You should have received a copy of the GNU Lesser General Public License
* along with this program.  If not, see <http://www.gnu.org/licenses/>.
*
***********************************************************************/

#include <stdio.h>
#include <string.h>
#include "logger.h"
#include "hashmap.h"
#include "linked_list.h"
#include "linkedhashmap.h"

struct linkedhashmap_data{
    linklist *list;
    map_t hashmap;
    int size;
};

linkedhashmap *newlinkedhashmap(){
    linkedhashmap *aux = (linkedhashmap *)malloc(sizeof(linkedhashmap));
    if(aux==NULL){ 
        wblprintf(LOG_CRITICAL,"LINKEDHASHMAP","Not enought memory\n");
        return NULL;
    }
    aux->hashmap=hashmap_new();
    aux->list=newlinkedlist();
    aux->size=0;
    return aux;
}

int get_lh_element(linkedhashmap *lh, char *key, element *value){
    element result;
    if(lh==NULL){
        wblprintf(LOG_CRITICAL,"LINKEDHASHMAP","LinkedHashmap not initiallized\n");
        return LH_ERROR;
    }
    if(hashmap_get(lh->hashmap,key,(any_t *)&result)!=MAP_MISSING){
        *value=result;
        return LH_OK;
    }
    *value=NULL;
    return LH_MISSING;
    
}

int add_lh_element(linkedhashmap *lh,char *key, element value){
    
    if(lh==NULL){
        wblprintf(LOG_CRITICAL,"LINKEDHASHMAP","LinkedHashmap not initiallized\n");
        return LH_ERROR;
    }
    element *result;
    if(hashmap_get(lh->hashmap,key,(any_t *)&result)==MAP_MISSING){
        lh->size++;
        addbeginlist(lh->list,value);
        hashmap_put(lh->hashmap,key,value);
        //printf("UNICO\n");
        //printf("TAM_LH_LISTA %d\n",lh->size);
        return LH_OK;
    }
    else{
        //AQUI ME ESTOY DEJANDO UNOS FREES (ME FALTA LIBERAR EL QUE SE SUSTITUYE) OJO!!!
        //element *obtained;
        //get_lh_element(lh,key,(element *)&obtained);
        //printf("REPETIDO\n");
        //printf("TAM_LH_LISTA %d\n",lh->size);
        //printf("TAM_LINKED_LIST_LISTA %d\n",getlengthlist(lh->list));
        //printf("   KEY %s\n",key);
        //printf("   DATA %d\n",*(int *)result);
        *result=*(element *)value;
        //printf("   NUEVO_DATA %d\n",*(int *)result);
        return LH_OK;
    }
}

void free_linkedhashmap(linkedhashmap *lh, PFree freedata, PFany freekey){

    freelist(lh->list,freedata);
    hashmap_iterate_keys(lh->hashmap,freekey,NULL);
    hashmap_free(lh->hashmap);
    free(lh);
}

linklist *lh_getlist(linkedhashmap *lh){
    return lh->list;
}

map_t lh_gethashmap(linkedhashmap *lh){
    return lh->hashmap;
}

/*
int free_lh_data(element elem){
    free(elem);
    return NODE_OK;
}

int free_lh_key(any_t nullpointer, any_t key){
    free(key);
    return MAP_OK;
}

int print_hashmap_values(any_t item,any_t data, any_t key){
    printf("KEY: %s\n",(char *)key);
    printf("VALUE: %d\n",*(int *)data);
    return MAP_OK;
}

int print_llist_values(element item, element data){
    printf("VALUE: %d\n",*(int *)data);
    return NODE_OK;
}

void print_lh_values(linkedhashmap *lh){
    printf("Iterador sobre el hashmap\n");
    hashmap_iterate_elements(lh->hashmap,&print_hashmap_values,NULL);
    printf("Iterador sobre la lista\n");
    linklist_iterate_data(lh->list,&print_llist_values,NULL);
}

int free_key(any_t item, any_t key){
    free(key);
    return MAP_OK;
}

int free_data(element data){
    free(data);
    return NODE_OK;
}

int compare_element(element a, element b){
    int *a1=(int *)a;
    int *b1=(int *)b;

    if(*a1<*b1)
        return -1;
    else
        if(*a1>*b1)
            return 1;
        else
            return 0;
}

int main(int argc, char *argv){
    int i=1;   
    linkedhashmap *lh=newlinkedhashmap();
    element elem;
    printf("INSERTANDO:...\n");
    for(;i<9;i++){
        if(i%2 == 0){
            char *key=malloc(sizeof(int)+sizeof(char));
            sprintf(key,"%d",i);
            if(get_lh_element(lh,key,(any_t *)&elem)==LH_MISSING){
                int *data=malloc(sizeof(int));
                *data=(i*10);
                add_lh_element(lh,key,data);
            }else free(key);
        }else{
            char *key=malloc(sizeof(int)+sizeof(char));
            sprintf(key,"%d",i);
            if(get_lh_element(lh,key,(any_t *)&elem)==LH_MISSING){
                int *data=malloc(sizeof(int));
                *data=(i+2);
                add_lh_element(lh,key,data);
            }else free(key);
        }
    }
    printf("ANTES DEL SORT\n");
    print_lh_values(lh);
    linklist_bubble_sort(lh->list,&compare_element);
    printf("DESPUES DEL SORT\n");
    print_lh_values(lh);

    printf("AHORA AÑADO REPETIDOS\n");
    int *a1,*a2,*a3,*a4;
    a1=malloc(sizeof(int));
    *a1=11;
    a2=malloc(sizeof(int));
    *a2=12;
    a3=malloc(sizeof(int));
    *a3=13;
    a4=malloc(sizeof(int));
    *a4=14;
    add_lh_element(lh,"1",a1);
    add_lh_element(lh,"2",a2);
    add_lh_element(lh,"3",a3);
    add_lh_element(lh,"4",a4);
    printf("DESPUES DE REPETIDOS\n");

    printf("ANTES DEL SORT\n");
    print_lh_values(lh);
    linklist_bubble_sort(lh->list,&compare_element);
    printf("DESPUES DEL SORT\n");
    print_lh_values(lh);
    
    free_linkedhashmap(lh,&free_data,&free_key);
}
*/