/***************************************************************************
*
*   File    : regex_plugin.c
*   Purpose : Implements a regex plugin with regex functionalities
*
*   Author: David Ruano, José Ramón Méndez
*
*
*   Date    : October  25, 2010
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

#include <stdlib.h>
#include <string.h>
#include <cpluff.h>
#include <regex.h>
#include <stdio.h>
#include "core.h"
#include "hashmap.h"
#include "regex_util.h"
#include "logger.h"
#include "parse_func_args.h"
#include "eml_parser.h"

struct regex_data{
    map_t regex_cache; //Is a cache of compiled regex
    function_t *funcs;
    cp_context_t *ctx;
};

typedef struct regex_data regex_data;

/**
 * Free a regex on the map
 */
int free_regex(void *nullpointer, void *regex, void *key){
    rgx_free((regex_t *)regex);
    free(key);
    return MAP_OK;
}

/**
 * Eval a regex on a content from email
 */
static int eval(void *_data, void *content, char *params, const char *flags){//, int parserType){
    //el msq es un char * ya que recibe el mail en modo raw.
    //Recibe un solo parametro que es el pattern
    char *target_content=(char *)content;
    regex_t *regex;
    char *expr, *tmp;
    regex_data *data=(regex_data *)_data;
    
    //printf("\nTARGET_CONTENT %s\n",target_content);
    
    function_arguments *arguments=parse_args(params,1);
    if(get_argument_type(arguments,0)!=TYPE_STRING){
        wblprintf(LOG_WARNING,"REGEX PLUGIN(eval)","Incorrect arguments %s\n", params);
        return 0;    	
    }

    expr=get_argument_content(arguments,0);

    if(data==NULL || hashmap_get(data->regex_cache,expr,(any_t *)&regex)==MAP_MISSING){
        regex=rgx_compile(expr);
        if (regex==NULL) {
            wblprintf(LOG_WARNING,"REGEX PLUGIN(eval)","Incorrect regular expression %s\n", params);
            return 0;
        }
        if (data!=NULL){
            tmp=malloc(sizeof(char)*(strlen(expr)+1)); //PUESTO YO
            strcpy(tmp,expr); //PUESTO YO
            hashmap_put(data->regex_cache,tmp,(any_t)regex);
            //printf("INSERTANDO KEY: %s\n",tmp);
        }
    }

    free_arguments(arguments);

    return rgx_match(regex,target_content);
    
}

/**
 * Create a plug-in instance.
 */
static void *create(cp_context_t *ctx){
    regex_data *data;
    data=malloc(sizeof(regex_data));
    data->ctx=ctx;
    
    data->regex_cache = hashmap_new();
    
    data->funcs=malloc(sizeof(function_t));
    data->funcs->function=&eval;
    data->funcs->conf_function=NULL;
    data->funcs->data=data;
    
    return data;
}

/**
 * Initializes and starts the plug-in.
 */
static int start(void *d) {
    regex_data *data=(regex_data *)d;
    //cp_context_t *ctx;

    //Dinamyc plugin initialization
    if (cp_define_symbol(data->ctx, "es_uvigo_ei_eval", data->funcs)==CP_OK)
       return CP_OK;
    else return CP_ERR_RESOURCE;
    
    return CP_OK;
}

/**
 * Release resources
 */
static void stop(void *d) {
    //regex_data *data=(regex_data *)d;
    
    //Free all compiled regex
    //hashmap_iterate_elements(data->regex_cache,&free_regex,NULL);
    
    //free the hashmaps
    //hashmap_free(data->regex_cache);
}

/**
 * Destroys a plug-in instance.
 */
static void destroy(void *d) {
    regex_data *data=(regex_data *)d;
    
    hashmap_iterate_elements(data->regex_cache,&free_regex,NULL);
    hashmap_free(data->regex_cache);
    
    free(data->funcs);
    free(data);
}

/* ------------------------------------------------------------------------
 * Exported classifier information
 * ----------------------------------------------------------------------*/
//CP_EXPORT function_t es_uvigo_ei_eval = { NULL, eval };

//CP_EXPORT function_t es_uvigo_ei_eval_header = { NULL, eval_header };

CP_EXPORT cp_plugin_runtime_t regex_plugin_runtime_functions = {create, start, stop, destroy};
