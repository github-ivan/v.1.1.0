/* 
 * File:   domain_parser.c
 * Author: David Ruano Ordas
 *
 */

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "eml_domain_parser.h"
#include "hashmap.h"
#include "logger.h"

#define BEGIN_DOMAIN 0
#define END_DOMAIN -1
#define END_PARSING -2

map_t get_eml_domains(char *domains){
    char *start_pointer=domains;
    char *begin=NULL;
    char *end=NULL;
    map_t domains_list=hashmap_new();

    int count=0;
    int status=END_DOMAIN;

    while(start_pointer[count]!='\0'){
        if(start_pointer[count]=='@'){
            if(status==END_DOMAIN){
                status=BEGIN_DOMAIN;
                begin=&start_pointer[count];
            }
            else wblprintf(LOG_WARNING,"DOMAIN PARSER","Error: Bad domain structure\n");
        }
        if( (start_pointer[count+1]=='>' || start_pointer[count+1]==',' ||
             start_pointer[count+1]==' ' || start_pointer[count+1]=='\0')
             && status==BEGIN_DOMAIN )
        {
            any_t nullpointer;
            status=END_DOMAIN;
            end=&start_pointer[count+1];
            char *domain=malloc(sizeof(char)*(end-begin+1));
            memcpy(domain,begin,sizeof(char)*(end-begin));
            domain[end-begin]='\0';
            if(hashmap_get(domains_list,domain,(any_t *)&nullpointer)==MAP_MISSING){
              hashmap_put(domains_list,domain,nullpointer);
            }
            else free(domain);
        }
        count++;
    }    
    return domains_list;

}

int free_eml_domain_key(any_t nullpointer,any_t key){
    free(key);
    return MAP_OK;
}

int print_eml_domain_key(any_t nullpointer,any_t key){
    printf("| %s",(char *)key);
    return MAP_OK;
}

int exist_eml_domain(map_t domains, char *key){
    any_t *nullpointer;
    return(hashmap_get(domains,key,(any_t*)&nullpointer)!=MAP_MISSING);
}

void free_eml_domains(map_t domains){
    hashmap_iterate_keys(domains,&free_eml_domain_key,NULL);
    hashmap_free(domains);
}

void print_eml_domains(map_t domains){
    printf("Domains");
    hashmap_iterate_keys(domains,&print_eml_domain_key,NULL);
    printf(" |\n");
}


char *get_eml_to_field(map_t eml){
    any_t to_field=NULL;
    
    if(hashmap_get(eml,"To",&to_field)!=MAP_MISSING)
        return to_field;
    if(hashmap_get(eml,"to",&to_field)!=MAP_MISSING)
        return to_field;
    if(hashmap_get(eml,"TO",&to_field)==MAP_MISSING)
        return to_field;
    if(hashmap_get(eml,"tO",&to_field)==MAP_MISSING)
        return to_field;
    return (char *)to_field;
}

/*
int main(int argc, char *argv[]){
    //printf("comunidade@uvigo.es, pas@uvigo.es\n");
    map_t domains;
    domains=get_domains("<comunidade@uvigo.es>, <pas@uviga.es>");
    printf("@uvigo.es %d\n",exist_domain(domains,"@uvigo.es"));
    printf("@uviga.es %d\n",exist_domain(domains,"@uviga.es"));
    printf("@pepe.es %d\n",exist_domain(domains,"@pepe.es"));
    free_domains(domains);
}
*/

