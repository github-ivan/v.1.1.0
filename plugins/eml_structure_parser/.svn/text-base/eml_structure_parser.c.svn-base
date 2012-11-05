/***************************************************************************
*
*   File    : eml_structure_parser.c
*   Purpose : Implements a plugin with functions to achieve header, body and full message
*
*   Author: David Ruano, Noemi Perez, Jose Ramon Mendez
*
*
*   Date    : October  20, 2010
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
#include <stdlib.h>
#include <cpluff.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "core.h"
#include "eml_parser.h"
#include "hashmap.h"
#include "header_parser.h"
#include <pthread.h>

struct eml_structure_parser_data{
      cp_context_t *ctx;
      parser_t *parsers[3];
      pthread_mutex_t *mutex4eml;
};

typedef struct eml_structure_parser_data eml_parser_data;

//Parse the msg using eml_parser.c
static void *header_parser(void *_data, const char *msg){
    eml_parser_data *data=(eml_parser_data *)_data;
    void *ret=NULL;
    void *raw=NULL;
    ret=parser_mail(msg);
    
    if (hashmap_get((rfc2822eml)ret,HEADER_PART,(any_t *)&raw)!=MAP_MISSING)
        hashmap_put((rfc2822eml)ret,RAW_ENTRY,raw);

    hashmap_put((rfc2822eml)ret,MUTEX_EML,data->mutex4eml);

    return ret;
}

//Parse the msg using eml_parser.c
static void *body_parser(void *_data, const char *msg){
    eml_parser_data *data=(eml_parser_data *)_data;
    void *ret=NULL;
    void *raw=NULL;
    ret=parser_mail(msg);

    if (hashmap_get((rfc2822eml)ret,BODY_PART,(any_t *)&raw)!=MAP_MISSING)
        hashmap_put((rfc2822eml)ret,RAW_ENTRY,raw);
         
    hashmap_put((rfc2822eml)ret,MUTEX_EML,data->mutex4eml);

    return ret;
}

//Parse the msg using eml_parser.c
static void *full_parser(void *_data, const char *msg){
    eml_parser_data *data=(eml_parser_data *)_data;
    void *ret=NULL;
    void *raw=NULL;
    
    ret=parser_mail(msg);

    if (hashmap_get((rfc2822eml)ret,FULL,&raw)!=MAP_MISSING)
        hashmap_put((rfc2822eml)ret,RAW_ENTRY,raw);

    hashmap_put((rfc2822eml)ret,MUTEX_EML,data->mutex4eml);

    return ret;
}

//Free data
void free_data(void *data){
    free_mail((rfc2822eml)data);
}

static void *create(cp_context_t *ctx){
   eml_parser_data *data=malloc(sizeof(eml_parser_data));
   data->ctx=ctx;
   
   //START
   
   data->mutex4eml=malloc(sizeof(pthread_mutex_t));
   pthread_mutex_init(data->mutex4eml, NULL);

   data->parsers[0]=malloc(sizeof(parser_t));
   data->parsers[0]->function=&header_parser;
   data->parsers[0]->data=data;
   data->parsers[0]->free_parser_data=&free_data;

   data->parsers[1]=malloc(sizeof(parser_t));
   data->parsers[1]->function=&body_parser;
   data->parsers[1]->data=data;
   data->parsers[1]->free_parser_data=&free_data;

   data->parsers[2]=malloc(sizeof(parser_t));
   data->parsers[2]->function=&full_parser;
   data->parsers[2]->data=data;
   data->parsers[2]->free_parser_data=&free_data;
   
   return data;
}

static int start(void *d){
    eml_parser_data *data=(eml_parser_data *)d;

    //Dinamyc plugin initialization
    if (cp_define_symbol(data->ctx, "es_uvigo_ei_header", data->parsers[0])==CP_OK &&
        cp_define_symbol(data->ctx, "es_uvigo_ei_body", data->parsers[1])==CP_OK &&
        cp_define_symbol(data->ctx, "es_uvigo_ei_full", data->parsers[2])==CP_OK )
       return CP_OK;
    else return CP_ERR_RESOURCE;	
}

static void stop(void *d) {
    freeEMLParser();
}

static void destroy(void *d) {
    eml_parser_data *data=(eml_parser_data *)d;
    pthread_mutex_destroy(data->mutex4eml);
    free(data->parsers[0]);
    free(data->parsers[1]);
    free(data->parsers[2]);
    free(data->mutex4eml);
    free(data);
}

/* ------------------------------------------------------------------------
 * Exported classifier information
 * ----------------------------------------------------------------------*/


CP_EXPORT cp_plugin_runtime_t eml_structure_parser_runtime_functions = {create, start, stop, destroy};
