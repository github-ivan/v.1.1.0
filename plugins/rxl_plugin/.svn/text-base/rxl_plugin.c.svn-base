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
#include <arpa/inet.h>

#include "core.h"
#include "hashmap.h"
#include "header_parser.h"
#include "eml_parser.h"
#include "logger.h"
#include "parse_func_args.h"
#include "cache.h"

#define INFO_ERROR 0
#define INFO_OK 1
#define NOT_CHECKED -1
#define NONE 0


//DEFAULT OPTIONS ASIGNED IF NO CONFIG SETTINGS ARE AVAILABLE.
#define DEFAULT_CACHE_SIZE 5
#define DEFAULT_TIMEOUT_SECONDS 0
#define DEFAULT_TIMEOUT_MILISECONDS 500
#define DEFAULT_WHITE_LIST NULL
#define DEFAULT_BLACK_LIST NULL
#define RXL_SECTION "RXL"

struct dns_result{
    int herrno;
    char **result_ip;
};
typedef struct dns_result dns_result;


struct rxl_config{
    int cache_size;
    int time_seconds;
    int time_miliseconds;
    map_t received_ip_wl;
    map_t received_ip_bl;
    int is_config_passed;
};

typedef struct rxl_config rxl_config;

struct rxl_data {
    cache_data *cache;
    cp_context_t *ctx;
    function_t *func;
    rxl_config *config;
    SPF_server_t *spf_server;
};
typedef struct rxl_data rxl_data;

void free_rxl_cache_data(element item){
    dns_result *dns_rr= (dns_result *)item;
    if(dns_rr){
        if(dns_rr->result_ip) free_parsed_ip(dns_rr->result_ip);
        free(dns_rr);
        dns_rr=NULL;
    }
}

int dns_rr_query(char *query, int n_octect, int octect_value,rxl_data *data){
    n_octect--;
    char str[INET_ADDRSTRLEN];
    int result=0;
    SPF_dns_rr_t *spf_dns_rr=SPF_dns_lookup(data->spf_server->resolver,query,ns_t_a,0);
    
    dns_result *dns_rr=malloc(sizeof(dns_result));
    dns_rr->result_ip=NULL;
    dns_rr->herrno=(spf_dns_rr->herrno==NETDB_SUCCESS || spf_dns_rr->herrno==NO_DATA);
    if (dns_rr->herrno){
        if( (dns_rr->result_ip=parse_ip((char *)inet_ntop(AF_INET,&(spf_dns_rr->rr[0]->a),
                                        str,INET_ADDRSTRLEN))) ==NULL){
            wblprintf(LOG_CRITICAL,"RXL_PLUGIN","Error parsing. Invalid IP\n");
            result=0;
        }else{
            if(n_octect>=0 && n_octect<4)
                result=(octect_value==atoi(get_octect(dns_rr->result_ip,n_octect)));
            else result=dns_rr->herrno;
        }
    }
    SPF_dns_rr_free(spf_dns_rr);
    if(push_cache(data->cache,query,&free_rxl_cache_data,dns_rr)==CACHE_UNDEF){
        free_rxl_cache_data(dns_rr);
        free(query);
    }
    return result;
}

int dns_rr_internal(int n_octect, int octect_value,dns_result *dns_rr){
   printf("dns_rr_internal\n");
   if(dns_rr->herrno==0){ 
       printf("IF - dns_rr_internal herrno==0\n");
       return 0;
   }
   else{
       n_octect--;
       printf("ELSE - ");
       printf("n_octect=%d\n",n_octect);
       if(n_octect>=0 && n_octect<4){
           if(dns_rr->result_ip==NULL){
               printf("result_ip==NULL\n"); return 0;
           }
           printf("antes atoi\n");
           return (octect_value==atoi(get_octect(dns_rr->result_ip,n_octect)));
       }
       return dns_rr->herrno;
   }
}

static int rxl_check(void *_data, void *content, char *params, const char *flags){

    rxl_data *data=(rxl_data *)_data;
    map_t parsed_content= (map_t) content;
    int header_num=1;
    int octect_num=0;
    int octect_value=0;
    char *domain;
    ip_info *info=NULL;
    char **ip=NULL;
    char *query=NULL;
    dns_result *result=NULL;
    char *raw_ip;
    int i;
    
    if(params!=NULL){
        int num_params=count_num_params(params);
        if(num_params<=0 && num_params>4){
            wblprintf(LOG_WARNING,"RXL_PLUGIN","Incorrect number of arguments.\n");
            return 0;
        }

        function_arguments *arguments=parse_args(params,num_params);
        if(get_argument_type(arguments,0)!=TYPE_STRING){
            wblprintf(LOG_WARNING,"RXL_PLUGIN","Incorrect argument type.\n");
            free_arguments(arguments);
            return 0;
        }

        (num_params==2 || num_params==4)?
            (header_num=atoi(get_argument_content(arguments,(num_params-1)))):
            (0);
        //printf("get_argument_content[0] %s\n",get_argument_content(arguments,0));
        //printf("get_argument_content[1] %s\n",get_argument_content(arguments,1));

        domain=get_argument_content(arguments,0);

        info=get_header_info(parsed_content,header_num);
        raw_ip=get_received_ip(info);
        if((ip=parse_ip(raw_ip))==NULL){
            wblprintf(LOG_CRITICAL,"RXL_PLUGIN","Unable to parse IP. Aborting plugin execution\n");
            free_arguments(arguments);
            free_ip(info);
            return 0;
        }
        
        if(num_params==3 || num_params==4){
            for(i=1;i<=num_params;i++){
                if(get_argument_type(arguments,i)!=TYPE_INT){
                    wblprintf(LOG_CRITICAL,"RXL_PLUGIN","Argument type (%d) is incorrect. Expected integer\n",i);
                    free_arguments(arguments);
                    free_parsed_ip(ip);
                    free_ip(info);
                    return 0;
                }
            }
            octect_num=atoi(get_argument_content(arguments,1));
            octect_value=atoi(get_argument_content(arguments,2));
        }
        
        query= malloc(sizeof(char)*(strlen(domain)+get_ip_size(ip)+5));
        sprintf(query,"%s.%s.%s.%s.%s",ip[3],ip[2],ip[1],ip[0],domain);
        
        printf("RXL SPF REQUEST: [%s] \n",query);
        
        free_arguments(arguments);
        free_parsed_ip(ip);
        free_ip(info);
        printf("Entro 1 - ELEMENT MISSING\n");
        if(peek_cache(data->cache,query,(element *)&result)==CACHE_ELEM_MISSING){
            if(data->config->received_ip_wl!=DEFAULT_WHITE_LIST || data->config->received_ip_bl!=DEFAULT_BLACK_LIST)
            {
                void *nullpointer;
                printf("Entro 1.1 - Whilelist\n");
                if(data->config->received_ip_wl!=DEFAULT_WHITE_LIST && 
                   hashmap_get(data->config->received_ip_wl,get_received_ip(info),
                               (any_t *)&nullpointer)!=MAP_MISSING){
                    free(query);
                    printf("Entro 1.1.1\n");
                    return 1;
                }
                printf("Entro 1.2 - Backlist\n");
                if(data->config->received_ip_bl!=DEFAULT_BLACK_LIST && 
                   hashmap_get(data->config->received_ip_bl,get_received_ip(info),
                               (any_t *)&nullpointer)!=MAP_MISSING){
                    free(query);
                    printf("Entro 1.2.1\n");
                    return 0;
                }
            }
            printf("Entro 1.3 - Si no esta ni en blacklist ni en whitelist\n");
            return dns_rr_query(query,octect_num,octect_value,data);
        }
        else{
            printf("Si el elemento está en la cache\n");
            free(query);
            return dns_rr_internal(octect_num,octect_value,result);
        }
    }
    else{
        wblprintf(LOG_WARNING,"RXL_PLUGIN","Not params expecified. Aborting execution...\n");
        return 0;
    }    
}


int free_rxl_cache(element elem){
    c_element cache_element=(c_element)elem;
    printf("----#####----\n");
    printf("----->Eliminando item %s\n",cache_element->key);
    free_rxl_cache_data(cache_element->data);
    free(cache_element->key);
    free(cache_element);
    return 0;
}

/**
 * Create a plug-in instance.
 */

static void set_rxl_config(void *_data, ini_file *config_file){
    rxl_data *data =(rxl_data *)_data;

    void *res;
    
    if(!data->config->is_config_passed){

        if(get_attribute_values_ini(config_file,RXL_SECTION,"cache_size",(void **)&res)==1){
           data->config->cache_size=atoi(res);
        }else {
            wblprintf(LOG_WARNING,"RXL_PLUGIN","Cache size not found. Asumming default\n");
            data->config->cache_size=DEFAULT_CACHE_SIZE;
        }

        if(get_attribute_values_ini(config_file,RXL_SECTION,"timeout_seconds",(void **)&res)==1){
            data->config->time_seconds=atoi(res);
        }else data->config->time_seconds=DEFAULT_TIMEOUT_SECONDS;

        if(get_attribute_values_ini(config_file,RXL_SECTION,"timeout_miliseconds",(void **)&res)==1){
            data->config->time_miliseconds=atoi(res);
        }else data->config->time_miliseconds=DEFAULT_TIMEOUT_MILISECONDS;

        if(get_attribute_values_ini(config_file,RXL_SECTION,"received_ip_wl",(void **)&res)>1){
            data->config->received_ip_wl=res;
        }else{
            data->config->received_ip_wl=DEFAULT_WHITE_LIST;
            wblprintf(LOG_WARNING,"RXL PLUGIN","IP whitelist not defined\n");
        }
        if(get_attribute_values_ini(config_file,RXL_SECTION,"received_ip_bl",(void **)&res)>1){
            data->config->received_ip_bl=res;
        }else{
            data->config->received_ip_bl=DEFAULT_WHITE_LIST;
            wblprintf(LOG_WARNING,"RXL PLUGIN","IP blacklist not defined\n");
        }

        (data->cache==NULL)?(data->cache=newcache(data->config->cache_size)):(0);
        
        data->config->is_config_passed=1;
        
    }else wblprintf(LOG_DEBUG,"RXL PLUGIN","Configuration function already executed\n");
}

static void *create(cp_context_t *ctx){
    rxl_data *data;
    data=(rxl_data *)malloc(sizeof(struct rxl_data));
    
    data->config=(rxl_config *)malloc(sizeof(rxl_config));
    data->config->is_config_passed=NONE;
    
    data->cache=NULL;    
    data->ctx=ctx;
    
    data->func=malloc(sizeof(function_t));

    data->func->function=&rxl_check;
    data->func->data=data;
    data->func->conf_function=&set_rxl_config;
    return data;
}

/**
 * Initializes and starts the plug-in.
 */
static int start(void *d) {

    rxl_data *data=(rxl_data *)d;
    
    data->spf_server = SPF_server_new(SPF_DNS_CACHE, 0);
    //Dinamyc plugin initialization
    if (cp_define_symbol(data->ctx, "es_uvigo_ei_rxl_check", data->func)==CP_OK)
       return CP_OK;
    else return CP_ERR_RESOURCE;
}

/**
 * Release resources
 */
static void stop(void *d) {

    //rxl_data *data=(rxl_data *)d;
    
    //SPF_server_free(data->spf_server);
    //free(data->func);
    //free(data->config);

}

/**
 * Destroys a plug-in instance.
 */
static void destroy(void *d) {
    
    rxl_data *data=(rxl_data *)d;
    SPF_server_free(data->spf_server);
    
    free_cache(data->cache,&free_rxl_cache);
    free(data->func);
    free(data->config);
    free(data);
}

/* ------------------------------------------------------------------------
 * Exported classifier information
 * ----------------------------------------------------------------------*/


CP_EXPORT cp_plugin_runtime_t rxl_plugin_runtime_functions = {create, start, stop, destroy};
