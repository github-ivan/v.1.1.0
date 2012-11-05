/* 
 * File:   parser_test.c
 * Author: drordas
 *
 * Created on 22 de octubre de 2012, 13:07
 */

#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>

#include "eml_parser.h"
#include "fileutils.h"

/*
 * 
 */
int main(int argc, char** argv) {
    
    char *email;
    void *raw=NULL;
    char *dumped=NULL;
    ae_load_eml_to_memory(argv[1],&email);
    
    rfc2822eml parsed_email=parser_mail(email);
    pthread_mutex_t *mutex4eml=malloc(sizeof(pthread_mutex_t));
    
    pthread_mutex_init(mutex4eml,NULL);

    if (hashmap_get((rfc2822eml)parsed_email,BODY_PART,(any_t *)&raw)!=MAP_MISSING)
        hashmap_put((rfc2822eml)parsed_email,RAW_ENTRY,raw);
    
    hashmap_put((rfc2822eml)parsed_email,MUTEX_EML,mutex4eml);
    
    dumped=dump_text(parsed_email);
    
    printf("%s\n",dumped);
    
    pthread_mutex_destroy(mutex4eml);
    
    free_mail(parsed_email);
    
    free(mutex4eml);
    
    free(email);
    
    freeEMLParser();
    
    return (EXIT_SUCCESS);
}

