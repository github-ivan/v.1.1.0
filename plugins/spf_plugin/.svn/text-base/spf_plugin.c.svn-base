/***************************************************************************                        
*
*   File    : spf_plugin.c
*   Purpose : Implements a spf plugin with several SPF functionalities
*            
*   Author: Noemi Perez, David Ruano, Jose Ramon Mendez
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <cpluff.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <spf2/spf.h>
//#include <pthread.h>
#include "core.h"
#include "hashmap.h"
#include "header_parser.h"
#include "eml_parser.h"
#include "logger.h"
#include "parse_func_args.h"
#include "cache.h"

#define SPF_DOMAIN_ERROR -2
#define SPF_IP_ERROR -1

#define DEFAULT_CACHE_SIZE 1
#define DEFAULT_WHITE_LIST NULL
#define DEFAULT_BLACK_LIST NULL
#define NONE 0

struct spf_config{
    int cache_size;
    map_t domain_wl;
    map_t domain_bl;
    map_t received_ip_wl;
    map_t received_ip_bl;
    int is_config_passed;
};

typedef struct spf_config spf_config;

struct check_spf_data{
  SPF_server_t    *spf_server;
  cache_data *cache;
  cp_context_t *ctx;
  function_t *funcs[5];
  spf_config *config; 
  //pthread_mutex_t mutex;
};

typedef struct check_spf_data spf_data;


void free_spf_cache_data(element item){
    free(item);
}

int spf_check(spf_data *data,map_t content,int header_pos){

    int *to_load;
    int result=SPF_RESULT_INVALID;
    char *key=NULL;
    ip_info *info=get_header_info(content,header_pos);

    if(data->spf_server==NULL){
        wblprintf(LOG_WARNING,"SPF PLUGIN","Error executing SPF Plugin\n");
        return SPF_RESULT_INVALID;
    }
    
    if(get_from_domain(info)==NULL || get_received_ip(info)==NULL){
        wblprintf(LOG_WARNING,"SPF PLUGIN","Cannot compute header. Aborting SPF....\n");
        free_ip(info);
        return SPF_RESULT_INVALID;
    }
    
    key=malloc(sizeof(char)*(strlen(get_received_ip(info))+
                             strlen(get_from_domain(info))+2));

    sprintf(key,"%s@%s",get_received_ip(info),get_from_domain(info));
    
    if(peek_cache(data->cache,key,(element *)&to_load)==CACHE_ELEM_MISSING){

        void *nullpointer;
        if(data->config->domain_wl!=DEFAULT_WHITE_LIST || data->config->domain_bl!=DEFAULT_BLACK_LIST ||
           data->config->received_ip_wl!=DEFAULT_WHITE_LIST || data->config->received_ip_bl!=DEFAULT_BLACK_LIST)
        {
            if(data->config->domain_wl!=DEFAULT_WHITE_LIST){
                if(hashmap_get(data->config->domain_wl,get_from_domain(info),(any_t *)&nullpointer)!=MAP_MISSING)
                    result=SPF_RESULT_PASS;
            }
            if(data->config->received_ip_wl!=DEFAULT_WHITE_LIST){
                if(hashmap_get(data->config->received_ip_wl,get_received_ip(info),(any_t *)&nullpointer)!=MAP_MISSING)
                    result=SPF_RESULT_PASS;
            }            
            if(data->config->domain_bl!=DEFAULT_BLACK_LIST){
                if(hashmap_get(data->config->domain_bl,get_from_domain(info),(any_t *)&nullpointer)!=MAP_MISSING)
                    result=SPF_RESULT_FAIL;
            }

            if(data->config->received_ip_bl!=DEFAULT_BLACK_LIST){
                if(hashmap_get(data->config->received_ip_bl,get_received_ip(info),(any_t *)&nullpointer)!=MAP_MISSING)
                    result=SPF_RESULT_FAIL;
            }
        }
        
        //printf("SPF 1.1\n");
        if(result==SPF_RESULT_INVALID){
            SPF_request_t   *spf_request = SPF_request_new(data->spf_server);
            SPF_response_t  *spf_response = NULL;
            //printf("GET RECEIVED IP: %s\n",get_received_ip(info));
            //printf("GET FROM DOMAIN IP: %s\n",get_from_domain(info));
            if(SPF_request_set_ipv4_str(spf_request, get_received_ip(info))){
                wblprintf(LOG_CRITICAL,"SPF LIBRARY","Invalid IP address\n");
                free(key);
                free_ip(info);
                return SPF_RESULT_INVALID;
            }
            
            if(SPF_request_set_env_from(spf_request, get_from_domain(info))){
                wblprintf(LOG_CRITICAL,"SPF LIBRARY","Invalid domain address\n");
                free(key);
                free_ip(info);
                return SPF_RESULT_INVALID;
            }

            //pthread_mutex_lock(&(data->mutex));
            
            SPF_request_query_mailfrom(spf_request, &spf_response);
            
            //printf("SPF 1.4\n");
            result=SPF_response_result(spf_response);
            //printf("SPF 1.5\n");
            (spf_response)?(SPF_response_free(spf_response)):(0);
            (spf_request)?(SPF_request_free(spf_request)):(0);
            //printf("SPF 1.6\n");
        }
        //printf("SPF 2.0 \n");
        free_ip(info);
        
        if(get_cache_size(data->cache)!=0){
            to_load=(int *)malloc(sizeof(int));
            *to_load=result;
            if(push_cache(data->cache,key,&free_spf_cache_data,to_load)==CACHE_UNDEF){
                free(key);
                free_spf_cache_data(to_load);
            }
        }else free(key);
        
        return result;
    }
    return *to_load;
}

static int spf_pass(void *_data, void *content, char *params, const char *flags){//, int parserType){

    spf_data *data=(spf_data *)_data;

    map_t parsed_content= (map_t) content;
    int header_num=1;

    if(params!=NULL){
        function_arguments *arguments=parse_args(params,1);
        if(get_argument_type(arguments,0)!=TYPE_INT){
            wblprintf(LOG_WARNING,"SPF PLUGIN(spf_pass)","Incorrect argument type\n");
        }
        else header_num=atoi(get_argument_content(arguments,0));
        free_arguments(arguments);
    }

    return (spf_check(data,parsed_content,header_num)==SPF_RESULT_PASS);
}


static int spf_none(void *_data, void *content, char *params, const char *flags){//, int parserType){

    spf_data *data=(spf_data *)_data;
    
    map_t parsed_content= (map_t) content;
    int header_num=1;

    if(params!=NULL){
        function_arguments *arguments=parse_args(params,1);
        if(get_argument_type(arguments,0)!=TYPE_INT){
            wblprintf(LOG_WARNING,"SPF PLUGIN(spf_none)","Incorrect argument type\n");
        }
        else header_num=atoi(get_argument_content(arguments,0));
        free_arguments(arguments);
    }

    return spf_check(data,parsed_content,header_num)==SPF_RESULT_NONE;
}

static int spf_neutral(void *_data, void *content, char *params, const char *flags){//, int parserType){

    spf_data *data=(spf_data *)_data;
    
    map_t parsed_content= (map_t) content;

    int header_num=1;

    if(params!=NULL){
        function_arguments *arguments=parse_args(params,1);
        if(get_argument_type(arguments,0)!=TYPE_INT){
            wblprintf(LOG_WARNING,"SPF PLUGIN(spf_neutral)","Incorrect argument type\n");
        }
        else header_num=atoi(get_argument_content(arguments,0));
        free_arguments(arguments);
    }

    return spf_check(data,parsed_content,header_num)==SPF_RESULT_NEUTRAL;
}

static int spf_fail(void *_data, void *content, char *params, const char *flags){//, int parserType){

    spf_data *data=(spf_data *)_data;
    
    map_t parsed_content= (map_t) content;

    int header_num=1;

    if(params!=NULL){
        function_arguments *arguments=parse_args(params,1);
        if(get_argument_type(arguments,0)!=TYPE_INT){
            wblprintf(LOG_WARNING,"SPF_PLUGIN(spf_fail)","Incorrect argument type\n");
        }
        else header_num=atoi(get_argument_content(arguments,0));
        free_arguments(arguments);
    }

    return spf_check(data,parsed_content,header_num)==SPF_RESULT_FAIL;
}

static int spf_softfail(void *_data, void *content, char *params, const char *flags){//, int parserType){

    spf_data *data=(spf_data *)_data;
    
    map_t parsed_content= (map_t) content;

    int header_num=1;

    if(params!=NULL){
        function_arguments *arguments=parse_args(params,1);
        if(get_argument_type(arguments,0)!=TYPE_INT){
            wblprintf(LOG_WARNING,"SPF_PLUGIN(spf_pass)","Incorrect argument type\n");
        }
        else header_num=atoi(get_argument_content(arguments,0));
        free_arguments(arguments);
    }

    return spf_check(data,parsed_content,header_num)==SPF_RESULT_SOFTFAIL;
}

int free_spf_cache(element elem){
    c_element cache_element=(c_element)elem;
    printf("----#####----\n");
    printf("----->Eliminando item %s\n",cache_element->key);
    free(cache_element->data);
    free(cache_element->key);
    free(cache_element);
    return 0;
}

static void set_spf_config(void *_data, ini_file *config_file){
    spf_data *data=(spf_data *)_data;

    if(!data->config->is_config_passed){
    
        void *res;

        if(get_attribute_values_ini(config_file,"SPF","cache_size",(void **)&res)==1){
            data->config->cache_size=atoi(res);
        }else data->config->cache_size=DEFAULT_CACHE_SIZE;

        if(get_attribute_values_ini(config_file,"SPF","domain_wl",(void **)&res)>1){
            data->config->domain_wl=res;
        }else{
            data->config->domain_wl=DEFAULT_WHITE_LIST;
            wblprintf(LOG_WARNING,"SPF_PLUGIN","Domain whitelist not defined\n");
        }
        if(get_attribute_values_ini(config_file,"SPF","domain_bl",(void **)&res)>1){
            data->config->domain_bl=res;
        }else{
            data->config->domain_bl=DEFAULT_WHITE_LIST;
            wblprintf(LOG_WARNING,"SPF_PLUGIN","Domain blacklist not defined\n");
        }

        if(get_attribute_values_ini(config_file,"SPF","received_ip_wl",(void **)&res)>1){
            data->config->received_ip_wl=res;
        }else{
            data->config->received_ip_wl=DEFAULT_WHITE_LIST;
            wblprintf(LOG_WARNING,"SPF_PLUGIN","IP whitelist not defined\n");
        }
        if(get_attribute_values_ini(config_file,"SPF","received_ip_bl",(void **)&res)>1){
            data->config->received_ip_bl=res;
        }else{
            data->config->received_ip_bl=DEFAULT_WHITE_LIST;
            wblprintf(LOG_WARNING,"SPF_PLUGIN","IP blacklist not defined\n");
        }

        if(get_cache_size(data->cache)!=data->config->cache_size)
           set_cache_size(data->cache,data->config->cache_size);
    
        data->config->is_config_passed=1;
    }else wblprintf(LOG_DEBUG,"SPF PLUGIN","Configuration function already executed\n");

    
}

/**
 * Create a plug-in instance.
 */
static void *create(cp_context_t *ctx){
    spf_data *data;
    data=(spf_data *)malloc(sizeof(spf_data));
    data->config=(spf_config *)malloc(sizeof(spf_config));
    data->config->is_config_passed=NONE;
    
    //pthread_mutex_init(&data->mutex,NULL);
    
    data->cache=newcache(DEFAULT_CACHE_SIZE);
    data->ctx=ctx;
    
    //START

    data->funcs[0]=malloc(sizeof(function_t));
    data->funcs[1]=malloc(sizeof(function_t));
    data->funcs[2]=malloc(sizeof(function_t));
    data->funcs[3]=malloc(sizeof(function_t));
    data->funcs[4]=malloc(sizeof(function_t));

    data->funcs[0]->function=&spf_pass;
    data->funcs[0]->data=data;
    data->funcs[0]->conf_function=&set_spf_config;

    data->funcs[1]->function=&spf_softfail;
    data->funcs[1]->data=data;
    data->funcs[1]->conf_function=&set_spf_config;

    data->funcs[2]->function=&spf_fail;
    data->funcs[2]->data=data;
    data->funcs[2]->conf_function=&set_spf_config;

    data->funcs[3]->function=&spf_none;
    data->funcs[3]->data=data;
    data->funcs[3]->conf_function=&set_spf_config;

    data->funcs[4]->function=&spf_neutral;
    data->funcs[4]->data=data;
    data->funcs[4]->conf_function=&set_spf_config;
   
    
    ctx=data->ctx;
    
    return data;
}

/**
 * Initializes and starts the plug-in.
 */
static int start(void *d) {
    
    spf_data *data=(spf_data *)d;
    if ( (data->spf_server = SPF_server_new(SPF_DNS_RESOLV, 0))==NULL ){
        wblprintf(LOG_CRITICAL,"SPF_PLUGIN","Error creating SPF structures\n");
    }
    
    //Dinamyc plugin initialization
    if (cp_define_symbol(data->ctx, "es_uvigo_ei_spf_pass", data->funcs[0])==CP_OK &&
        cp_define_symbol(data->ctx, "es_uvigo_ei_spf_softfail", data->funcs[1])==CP_OK &&
        cp_define_symbol(data->ctx, "es_uvigo_ei_spf_fail", data->funcs[2])==CP_OK &&
        cp_define_symbol(data->ctx, "es_uvigo_ei_spf_none", data->funcs[3])==CP_OK &&
        cp_define_symbol(data->ctx, "es_uvigo_ei_spf_neutral", data->funcs[4])==CP_OK )
       return CP_OK;
    else return CP_ERR_RESOURCE;
}

/**
 * Release resources
 */
static void stop(void *d) {
    spf_data *data=(spf_data *)d;
    SPF_server_free(data->spf_server);
}

/**
 * Destroys a plug-in instance.
 */
static void destroy(void *d) {
    //check_spf_data *data=(check_spf_data *)d;
    //free_cache(data->cache,&free_bayes_cache);
    spf_data *data=(spf_data *)d;
    
    //pthread_mutex_destroy(&data->mutex);
    
    free_cache(data->cache,&free_spf_cache);
    free(data->config);
    
    free(data->funcs[0]);
    free(data->funcs[1]);
    free(data->funcs[2]);
    free(data->funcs[3]);
    free(data->funcs[4]);
    
    free(data);
}

/* ------------------------------------------------------------------------
 * Exported classifier information
 * ----------------------------------------------------------------------*/

//CP_EXPORT function_t es_uvigo_ei_spf_pass = { NULL, spf_pass };

//CP_EXPORT function_t es_uvigo_ei_spf_fail = { NULL, spf_fail };

CP_EXPORT cp_plugin_runtime_t spf_plugin_runtime_functions = {create, start, stop, destroy};