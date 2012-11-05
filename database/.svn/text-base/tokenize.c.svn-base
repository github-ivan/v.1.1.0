/***************************************************************************
*
*   File    : tokenize.c
*   Purpose : Realizes the division into a tokens of an e-mail.
*
*
*   Author  : David Ruano Ordás
*   Date    : November  02, 2010
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


/*---------------------------------------------------------------------------
   	       							     INCLUDES
 ---------------------------------------------------------------------------*/

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "string_util.h"
#include "logger.h"
#include "tokenize.h"

/*---------------------------------------------------------------------------
                                                                    FUNCTIONS
 ---------------------------------------------------------------------------*/

/**
 * Tokenizes a message and stores each different token in a hashmap with its
 * number of duplicates.
 */
map_t tokenize(char *email){
    char *email_copy = NULL;
    char *token;
    int *numtoken;
    map_t tokenmap = hashmap_new();
    if(email==NULL){
        return tokenmap;
    }
    int *count=malloc(sizeof(int));

    *count=0;
    email_copy= (char*) malloc(sizeof(char)*(strlen(email)+1));
    if(email_copy==NULL){
        wblprintf(LOG_CRITICAL,"TOKENIZE","Not enought memory\n");        
        free(email_copy);
        free(count);
        return tokenmap;
    }

    strcpy(email_copy,trim(email));
    token=strtok(email_copy," \n\t");
    
    if(token==NULL){ 
        wblprintf(LOG_CRITICAL,"TOKENIZE","Not usable tokens\n");        
        free(email_copy);
        free(count);
        return tokenmap;
    }
    else hashmap_put(tokenmap,INIT_TOKEN,(any_t)token);
    
    while(token!=NULL){
        if(strcmp(token,INIT_TOKEN)!=0 && strcmp(token,COUNT_TOKEN)!=0){
            *count=*count+1;
            if(hashmap_get(tokenmap,token,(any_t *)&numtoken)==MAP_MISSING){
                numtoken =malloc(sizeof(int));
                *numtoken=1;
                hashmap_put(tokenmap,token,(any_t)numtoken);
                //printf("TOKEN: (%s) No esta en el hashmap y su valor es: (%d)\n",token,*numtoken);
            }else{
                *numtoken=*numtoken+1;
                //printf("TOKEN: (%s) Esta en el hashmap y su valor es: (%d)\n",token,*numtoken);
                hashmap_put(tokenmap,token,(any_t)numtoken);
            }
        }
        token=strtok(NULL," \n\t");
    }
    hashmap_put(tokenmap,COUNT_TOKEN,(any_t)count);
    return tokenmap;
}

/**
 * Data liberation for tokenize function.
 */
int free_tokenize_data(any_t item, any_t data, any_t key){
    free(data);
    return MAP_OK;
}

/**
 * Tokens hashmap liberations.
 */
void free_tokenize(map_t tokens){
    //hashmap_iterate_elements(tokens,&print_tokenize,NULL);
    if(tokens!=NULL){
        hashmap_iterate_elements(tokens,&free_tokenize_data,NULL);
        hashmap_free(tokens);
    }
}

/*
int printInfo(any_t item, any_t data, any_t key){
    printf("KEY: %s\n",(char *)key);
    if(strcmp((char *)key,INIT_TOKEN)==0)
        printf("Data: %s\n",(char *)data);
    else
        printf("Data: %d\n",(int)data);
    return MAP_OK;
}

int main(){

    printf("======= MAIN =======\n");
    map_t tok;
    printf("que de que que de a\n\n\t pepe pepe luis a a\n");
    tok=tokenize("que de que que de a\n\n\t pepe pepe luis a a\n");
    hashmap_iterate_elements(tok,&printInfo,NULL);
    free_tokenize(tok);
    printf("BLA\n");
    hashmap_iterate_elements(tok,&printInfo,NULL);
    return 1;
}
*/