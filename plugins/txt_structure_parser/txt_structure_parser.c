/***************************************************************************
*
*   File    : txt_structure_parser.c
*   Purpose : Implements a plugin with functions to achieve header, body and full message
*
*   Author: David Ruano
*
*
*   Date    : February  28 2011
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
#include "hashmap.h"
#include <pthread.h>
#include "txt_parser.h"

struct txt_structure_parser_data{
      cp_context_t *ctx;
      parser_t *parsers;
      pthread_mutex_t *mutex4txt;
};

typedef struct txt_structure_parser_data txt_parser_data;

//Parse the msg using eml_parser.c
static void *txt_parser(void *_data, const char *msg){
    //txt_parser_data *data=(txt_parser_data *)_data;
    //printf("EXECUTING TXT PARSER\n");
    //printf("Result: %s\n",(char *)msg);
    return ((void *)parser_txt((char *)msg));
}

//Parse the msg using eml_parser

//Free data
void free_data(void *data){
    
    if(data!=NULL) free_parser_txt(data);
}

static void *create(cp_context_t *ctx){
   txt_parser_data *data=malloc(sizeof(txt_parser_data));
   data->ctx=ctx;
   
   //START
   //printf("CREATING TXT PLUGIN\n");
   //data->mutex4txt=malloc(sizeof(pthread_mutex_t));
   //pthread_mutex_init(data->mutex4txt, NULL);

   data->parsers=(parser_t *)malloc(sizeof(parser_t));

   data->parsers->function=&txt_parser;
   data->parsers->data=data;
   data->parsers->free_parser_data=&free_data;
   
   return data;
}

static int start(void *d){
    txt_parser_data *data=(txt_parser_data *)d;
    //printf("STARTING TXT PLUGIN\n");
    //Dinamyc plugin initialization
    return cp_define_symbol(data->ctx, "es_uvigo_ei_txt", data->parsers);
}

static void stop(void *d) {
    //free_data(d);
    //txt_parser_data *data = (txt_parser_data *)d;
    //free_parser_txt(data->parsed_content);
}

static void destroy(void *d) {
    txt_parser_data *data=(txt_parser_data *)d;
    
    //printf("DESTROYING PLUGIN\n");
    //pthread_mutex_destroy(data->mutex4txt);
    //(data->mutex4txt!=NULL)?(free(data->mutex4txt)):(0);
    
    free(data->parsers);
    free(data);
}

/* ------------------------------------------------------------------------
 * Exported classifier information
 * ----------------------------------------------------------------------*/

CP_EXPORT cp_plugin_runtime_t txt_structure_parser_runtime_functions = {create, start, stop, destroy};
