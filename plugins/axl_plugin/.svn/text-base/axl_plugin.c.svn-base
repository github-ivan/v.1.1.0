/***************************************************************************
*
*   File    : axl_plugin.c
*   Purpose :
*
*
*   Author  : David Ruano Ordás
*   Date    : October 2011
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
#include <stdio.h>
#include <db.h>
#include <cpluff.h>
#include "core.h"
#include "learn_axl.h"
#include "parse_func_args.h"
#include "logger.h"
#include "cache.h"
#include "iniparser.h"
#include "header_parser.h"


#define DEFAULT_AXL_DATABASE_PATH "axl.db"
#define AXL_ENV_PATH "database/"
#define DEFAULT_AXL_CACHE_SIZE 5
#define DEFAULT_AXL_HEADER 0
#define DISABLE_AXL_HEADER -1
#define NONE 0

struct axl_config{
  int cache_size;
  char *database_path;
  int default_header;  
  int is_config_passed;
};

typedef struct axl_config axl_config;

struct axl_data{
  DB *dbp;
  DB_ENV *env;
  cache_data *cache;
  function_t *funcs[2];
  eventhandler_t *events;
  cp_context_t *ctx;
  axl_config *config;
  int header_num;
};

typedef struct axl_data axl_data;

void free_axl_cache_data(element item);

//static int check_auto_whitelist(void *_data, void *content, char *params, const char *flags){
static int check_auto_whitelist(void *_data, void *content, char *params, const char *flags){//, int parserType){

    axl_data *data=(axl_data *)_data;
    axl_info *result;

    map_t parsed_content= (map_t) content;
    
    if(params!=NULL){
        function_arguments *arguments=parse_args(params,1);
        if(get_argument_type(arguments,0)!=TYPE_INT){
            wblprintf(LOG_WARNING,"AXL PLUGIN","Incorrect argument type\n");
            data->header_num=1;
        }
        else data->header_num=atoi(get_argument_content(arguments,0));
        free_arguments(arguments);
    }

    ip_info *info=get_header_info(parsed_content,data->header_num);

    char *key=malloc(sizeof(char)*(strlen(get_received_ip(info))+
                             strlen(get_from_domain(info))+2));

    sprintf(key,"%s@%s",get_received_ip(info),get_from_domain(info));
    free_ip(info);

    if(peek_cache(data->cache,key,(element *)&result)==CACHE_ELEM_MISSING){
       if(get_axl_data(data->dbp,key,&result)==TOKEN_MISSING){
           free(key);
           //printf("NO ESTÄ. POR TANTO 1");
           return 1; //SI NO ESTA HAY DECIR QUE ES HAM.
       }
       else{
           //printf("SI ESTA, MIRO LO QUE VALE %d=>%d",get_axl_ham(result),get_axl_spam(result));
           push_cache(data->cache,key,&free_axl_cache_data,result);
           return get_axl_ham(result)>=get_axl_spam(result);
       }
    }else return get_axl_ham(result)>=get_axl_spam(result);
}

static int check_auto_blacklist(void *_data, void *content, char *params, const char *flags){//, int parserType){
    axl_data *data=(axl_data *)_data;
    axl_info *result;

    map_t parsed_content= (map_t) content;

    if(params!=NULL){
        function_arguments *arguments=parse_args(params,1);
        if(get_argument_type(arguments,0)!=TYPE_INT){
            wblprintf(LOG_WARNING,"AXL PLUGIN","Incorrect argument type\n");
            data->header_num=1;
        }
        else data->header_num=atoi(get_argument_content(arguments,0));
        free_arguments(arguments);
    }

    ip_info *info=get_header_info(parsed_content,data->header_num);

    char *key=malloc(sizeof(char)*(strlen(get_received_ip(info))+
                             strlen(get_from_domain(info))+2));

    sprintf(key,"%s@%s",get_received_ip(info),get_from_domain(info));
    free_ip(info);
    if(peek_cache(data->cache,key,(element *)&result)==CACHE_ELEM_MISSING){
       if(get_axl_data(data->dbp,key,&result)==TOKEN_MISSING){
           free(key);
           return 0; //SI NO ESTA HAY DECIR QUE NO ES SPAM.
       }else{
           push_cache(data->cache,key,&free_axl_cache_data,result);
           return get_axl_spam(result)>get_axl_ham(result);
       }
    }else return get_axl_spam(result)>get_axl_ham(result);
}

void free_axl_cache_data(element item){
    free(item);
}

int free_axl_cache(element elem){
    c_element cache_element=(c_element)elem;
    free(cache_element->data);
    free(cache_element->key);
    free(cache_element);
    return 0;
}

static void set_axl_config(void *_data, ini_file *config_file){
    axl_data *data=(axl_data *)_data;
    
    if(!data->config->is_config_passed){
        
        void *res;

        if(get_attribute_values_ini(config_file,"AXL","cache_size",(void **)&res)>0){
            data->config->cache_size=atoi(res);
        }else data->config->cache_size=DEFAULT_AXL_CACHE_SIZE;

        if(get_attribute_values_ini(config_file,"AXL","database_path",(void **)&res)>0){
            data->config->database_path=res;
        }else data->config->database_path=DEFAULT_AXL_DATABASE_PATH;

        if(get_cache_size(data->cache)!=data->config->cache_size)
           set_cache_size(data->cache,data->config->cache_size);
        
        if(get_attribute_values_ini(config_file,"AXL","default_header",(void **)&res)>0)
            data->config->default_header=atoi(res);
        //}else data->config->cache_size=DEFAULT_AXL_HEADER;

        if(data->dbp==NULL){
            if(create_env(&(data->env),AXL_ENV_PATH)!=DB_OK){
                wblprintf(LOG_CRITICAL,"AXL_PLUGIN: ","Cannot create environment\n");
            }
            //printf("ENVIRONMENT CREADO\n");
            if(create_db_conexion(&(data->dbp),data->env,data->config->database_path,DB_CREATE)!= DB_OK)
                wblprintf(LOG_CRITICAL,"AXL_PLUGIN","Cannot open database\n");
            //  printf("DATABASE CREADO\n");
        } 
        data->config->is_config_passed=1;
    }else wblprintf(LOG_DEBUG,"AXL PLUGIN","Configuration util already executed\n");

}

static void autolearn_axl(void *_data, void *_content, const int isspam){

        axl_data *data=(axl_data *)_data;

        (data->header_num==DISABLE_AXL_HEADER)?(data->header_num=data->config->default_header):(0);

        map_t parsed_content= (map_t) _content;
        ip_info *info=get_header_info(parsed_content,data->header_num);

        char *key=malloc(sizeof(char)*(strlen(get_received_ip(info))+
                                       strlen(get_from_domain(info))+2));

        sprintf(key,"%s@%s",get_received_ip(info),get_from_domain(info));

        //printf("%s@%s",get_received_ip(info),get_from_domain(info));

        add_axl_data(data->dbp,key,isspam);
        //printf("[4]\n");
        (info!=NULL)?(free_ip(info)):(0);
        (key!=NULL)?(free(key)):(0);

        (isspam)?
        (wblprintf(LOG_INFO,"AXL EVENTHANDLER","Trainning message as spam...\n")):
        (wblprintf(LOG_INFO,"AXL EVENTHANDLER","Trainning message as ham...\n"));
        //if(close_db_conexion(&(data->dbp),data->config->database_path)!=DB_OK){
        //    wblprintf(LOG_WARNING,"AWL EVENTHANDLER","Error closing databases.\n");
        //}
        //if((data->env)->close(data->env,0)!=0){
        //    wblprintf(LOG_WARNING,"AWL EVENTHANDLER","Error closing environment.\n");
        //}
      // }
    //}
        
}

static void *create(cp_context_t *ctx){//Abrir bd
    axl_data *data;
    
    data=(axl_data *)malloc(sizeof(axl_data));
    data->config=(axl_config *)malloc(sizeof(axl_config));
    data->config->is_config_passed=NONE;
    
    data->cache=newcache(DEFAULT_AXL_CACHE_SIZE);
    data->dbp=NULL;
    data->ctx=ctx;
    data->header_num=DISABLE_AXL_HEADER;
    
    //START
    
    data->config->default_header=DEFAULT_AXL_HEADER;
    
    data->funcs[0]=malloc(sizeof(function_t));
    data->funcs[0]->function=&check_auto_whitelist;
    data->funcs[0]->data=data;
    data->funcs[0]->conf_function=&set_axl_config;
    
    data->funcs[1]=malloc(sizeof(function_t));
    data->funcs[1]->function=&check_auto_blacklist;
    data->funcs[1]->data=data;
    data->funcs[1]->conf_function=&set_axl_config;    
    
    data->events=(eventhandler_t *)malloc(sizeof(eventhandler_t));
    data->events->function=&autolearn_axl;
    data->events->data=data;
    data->events->parser_name="header"; 
    
    return data;
}

static int start(void *d){
    axl_data *data=(axl_data *)d;
    //cp_context_t *ctx;
    
    //ctx=data->ctx;

    //Dinamyc plugin initialization
    if (cp_define_symbol(data->ctx, "es_uvigo_ei_check_auto_whitelist", data->funcs[0])==CP_OK &&
        cp_define_symbol(data->ctx, "es_uvigo_ei_check_auto_blacklist", data->funcs[1])==CP_OK &&
        cp_define_symbol(data->ctx, "es_uvigo_ei_autolearn_axl", data->events)==CP_OK)
       return CP_OK;
    else {
        wblprintf(LOG_CRITICAL,"AXL PLUGIN","Functions could not be registered.\n");
        return CP_ERR_RESOURCE;
    }
}

static void stop(void *d) {
    //axl_data *data=(axl_data *)d;
    //free(data->funcs[0]);
    //free(data->funcs[1]);
    //free(data->config);
    //free(data->events);
}
//Cerrar bd

static void destroy(void *d) {
    axl_data *data=(axl_data *)d;
    //liberar cache. FALTA!!

    if(close_db_conexion(&(data->dbp), data->config->database_path)!=DB_OK){
        wblprintf(LOG_WARNING,"AXL PLUGIN","Error closing databases.\n");
    }
    if((data->env)->close((data->env),0)!=0){
        wblprintf(LOG_WARNING,"AXL PLUGIN","Error closing environment.\n");
    }
    free_cache(data->cache,&free_axl_cache);
    free(data->funcs[0]);
    free(data->funcs[1]);
    free(data->config);
    free(data->events);
    
    free(d);
}

CP_EXPORT cp_plugin_runtime_t axl_plugin_runtime_functions = {create, start, stop, destroy};