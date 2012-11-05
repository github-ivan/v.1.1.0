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

//#include <pthread.h>
#include "hashmap.h"
#include "header_parser.h"
#include "eml_parser.h"
#include "logger.h"
#include "parse_func_args.h"
#include "spf_plugin.h"


#define SPF_DOMAIN_ERROR -2
#define SPF_IP_ERROR -1

#define DEFAULT_CACHE_SIZE 1
#define DEFAULT_WHITE_LIST NULL
#define DEFAULT_BLACK_LIST NULL
#define NONE 0


void free_spf_cache_data(element item){
    free(item);
}

int spf_check(spf_data *data,map_t content,int header_pos){

    //int *to_load;
    SPF_server_t *spf_server=NULL;
    
    if ( (spf_server=SPF_server_new(SPF_DNS_RESOLV, 0))==NULL ){
        wblprintf(LOG_CRITICAL,"SPF_PLUGIN","Error creating SPF structures\n");
    }
    
    char *key=NULL;
    ip_info *info=get_header_info(content,header_pos);
    
    //if(data->spf_server==NULL){
    if(spf_server==NULL){
        wblprintf(LOG_WARNING,"SPF PLUGIN","Error executing SPF Plugin\n");
        free(info);
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
    
    //if(peek_cache(data->cache,key,(element *)&to_load)==CACHE_ELEM_MISSING){
        
        //printf("SPF 1.1\n");
        //if(result==SPF_RESULT_INVALID){
            //SPF_request_t   *spf_request = SPF_request_new(data->spf_server);
            SPF_request_t   *spf_request = SPF_request_new(spf_server);
            SPF_response_t  *spf_response = NULL;
            printf("GET RECEIVED IP: %s\n",get_received_ip(info));
            printf("GET FROM DOMAIN IP: %s\n",get_from_domain(info));
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
            SPF_result_t result=SPF_response_result(spf_response);
            printf("SPF 1.5\n");
            SPF_response_free(spf_response);
            SPF_request_free(spf_request);
            SPF_server_free(spf_server);
            printf("SPF 1.6\n");
        //}
        //printf("SPF 2.0 \n");
        free_ip(info);
        
        //if(get_cache_size(data->cache)!=0){
        //    to_load=(int *)malloc(sizeof(int));
        //    *to_load=result;
        //    if(push_cache(data->cache,key,&free_spf_cache_data,to_load)==CACHE_UNDEF){
        //        free(key);
        //        free_spf_cache_data(to_load);
        //    }
        //}else free(key);
        free(key);
        //if(to_load!=NULL) free_spf_cache_data(to_load);
        return result;
    //}
    //return *to_load;
}

int spf_pass(void *_data, void *content, char *params){

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


int spf_none(void *_data, void *content, char *params){//, int parserType){

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

int spf_neutral(void *_data, void *content, char *params){

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

int spf_fail(void *_data, void *content, char *params){

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

int spf_softfail(void *_data, void *content, char *params){

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

/**
 * Create a plug-in instance.
 */
/*
spf_data *create_spf(){
    spf_data *data=(spf_data *)malloc(sizeof(spf_data));
    
    //pthread_mutex_init(&data->mutex,NULL);
    
    data->cache=newcache(0);
    
    if ( (data->spf_server = SPF_server_new(SPF_DNS_CACHE, 0))==NULL ){
        wblprintf(LOG_CRITICAL,"SPF_PLUGIN","Error creating SPF structures\n");
    }
    return data;
}
*/


//void destroy_spf(spf_data *data) {

//    SPF_server_free(data->spf_server);

//    free_cache(data->cache,&free_spf_cache);

//    free(data);
//}