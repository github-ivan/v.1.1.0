/* 
 * File:   parser_txt.c
 * Author: drordas
 *
 * Created on 6 de marzo de 2012, 16:36
 */

#include <stdio.h>
#include <stdlib.h>
#include "logger.h"
#include "hashmap.h"
#include "linked_list.h"
#include "string_util.h"
#include "txt_parser.h"

char *parser_txt(char *txt){
    
    char *toret=malloc(sizeof(char)*(strlen(txt)+1));
    //strcpy(toret,txt);
    memcpy(toret,txt,strlen(txt)*sizeof(char));
    toret[strlen(txt)]='\0';
    
    return toret;
}

void free_parser_txt(char *txt){
    if(txt!=NULL){
        free(txt);
        txt=NULL;
    }
}


