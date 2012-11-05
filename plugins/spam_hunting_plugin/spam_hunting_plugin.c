/* 
* File:   spam_hunting_plugin.c
* Author: Noemí Pérez Díaz
*   Date    : April  1, 2011
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
#include <parse_func_args.h>
#include "learn_spamhunting.h"
#include "cache.h"
#include "core.h"
#include "logger.h"
#include "hashmap.h"
#include "tokenize.h"
#include "linked_list.h"
#include "linkedhashmap.h"
#include "sh_utils.h"
#include "eml_parser.h"
#include "sha1.h"
#include "fileutils.h"
#include "iniparser.h"
#include "db_utils.h"

#define DEFAULT_CACHE_SIZE 5

/*---------------------------------------------------------------------------
                                                                  GLOBAL VARS
 ---------------------------------------------------------------------------*/

#define TOKENS_PATH "tokens.db"
#define PAIRS_PATH "pairs.db"
#define EMAIL_PATH "email.db"
#define SH_ENV_PATH "database/"
#define NONE 0


/* A container for bayes configuration parameters.*/
struct sh_config{
  int cache_size;
  int is_config_passed;
  //char *database_path;
};

/* A short hand typedef for bayes_config structure */
typedef struct sh_config sh_config;

struct sh_data{
  sh_config *config;
  cache_data *cache;
  spamhunting_db *db;
  eventhandler_t *events;
  function_t *funcs;
  cp_context_t *ctx;
};

typedef struct sh_data sh_data;

int hunt_spam(void *_data, void *content, char *params, const char *flags, int parserType);

static void *create(cp_context_t *ctx){
    sh_data *retval;
    
    retval=(sh_data *)malloc(sizeof(sh_data));
    retval->cache=newcache(DEFAULT_CACHE_SIZE);
    retval->config=(sh_config *)malloc(sizeof(sh_config));
    retval->config->is_config_passed=NONE;
    
    retval->db=NULL;
    retval->ctx=ctx;
    return retval;
}

static void set_sh_config(void *_data, ini_file *config_file){
    sh_data *data=(sh_data *)_data;
    //DB_ENV *env;
    
    if(!data->config->is_config_passed){
        void *res;

        if(get_attribute_values_ini(config_file,"SPAMHUNTING PLUGIN","cache_size",(void **)&res)>0){
            data->config->cache_size=atoi(res);
        }else data->config->cache_size=DEFAULT_CACHE_SIZE;

        if(get_cache_size(data->cache)!=data->config->cache_size)
           set_cache_size(data->cache,data->config->cache_size);

        data->db=(spamhunting_db *)malloc(sizeof(spamhunting_db));
        //if(data->db==NULL){
            //data->db->tokensdb=NULL;//MIRAR ESTAS TRES LINEAS SI ESTAN BIEN
            //data->db->emaildb=NULL;
            //data->db->pairsdb=NULL;
            //data->db->env=malloc(sizeof(DB_ENV *));

        if(create_env(&(data->db->env),SH_ENV_PATH)!=DB_OK)
            wblprintf(LOG_CRITICAL,"SPAMHUNTING PLUGIN","Cannot create environment\n");

        if(create_db_conexion(&(data->db->tokensdb), (data->db->env), TOKENS_PATH, DB_CREATE)!= DB_OK)// (data->db->env), tokens_path,DB_CREATE)!= DB_OK){
            wblprintf(LOG_CRITICAL,"SPAMHUNTING PLUGIN","Cannot open tokens database\n");

        if(create_db_dup_conexion(&(data->db->pairsdb), (data->db->env), PAIRS_PATH, DB_CREATE)!= DB_OK)//(data->db->env), pairs_path,DB_CREATE)!= DB_OK){
            wblprintf(LOG_CRITICAL,"SPAMHUNTING PLUGIN","Cannot open pairs database\n");

        if(create_db_conexion(&(data->db->emaildb), (data->db->env), EMAIL_PATH, DB_CREATE)!= DB_OK)//(data->db->env), email_path,DB_CREATE)!= DB_OK){
            wblprintf(LOG_CRITICAL,"SPAMHUNTING PLUGIN","Cannot open email database\n");
            
        //}
        //else{
        //    wblprintf(LOG_CRITICAL,"SPAMHUNTING PLUGIN","Not enought memmory to allocate data\n");
        //}
        data->config->is_config_passed=1;
        
    }else wblprintf(LOG_DEBUG,"SPAMHUNTING PLUGIN","Configuration function already executed\n");   
    /*
    printf("MIN_NSPAM: %d\n",data->config->min_nspam);
    printf("MIN_NHAM: %d\n",data->config->min_nham);
    printf("CACHE_SIZE: %d\n",data->config->cache_size);
    printf("DB_PATH_CONFIGURE: %s\n",data->config->database_path);
    printf("SIGNIFICAN_TOKENS: %d\n",data->config->require_significant_tokens);
    */
}

int hunt_spam(void *_data, void *content, char *params, const char *flags, int parserType){
    
    sh_data *data=(sh_data *)_data;
    
    if(parserType==EML_PARSER){

        char *target_content=dump_text(content);
        return (scan_sh(target_content,data->db));
    }
    else{
        wblprintf(LOG_INFO,"SPAMHUNTING PLUGIN","TXT PARSER REQUIRED. Aborting execution...\n");
        return 0;
    }
    //printf("RESULTADO ES: %d\n",result);
    //printf("EXECUTING SPAM_HUNTING\n");
    //return result;
}

int print_info(any_t item, any_t data, any_t key){
    printf("Key %s\n",(char *)key);
    printf("Data: %s\n",(char *)data);
    return MAP_OK;
}

static void autolearn_spam_hunting(void *_data, void *_content, const int isspam){
    
    sh_data *data=(sh_data *)_data;

    data->db=(spamhunting_db *)malloc(sizeof(spamhunting_db));
    
/*
    if(data->db!=NULL){
        data->db->tokensdb=NULL;//MIRAR ESTAS TRES LINEAS SI ESTAN BIEN
        data->db->emaildb=NULL;
        data->db->pairsdb=NULL;
        //data->db->env=malloc(sizeof(DB_ENV *));
        if(create_env(&(data->db->env),SH_ENV_PATH)!=DB_OK){
            wblprintf(LOG_CRITICAL,"SPAMHUNTING EVENTHANDLER","Cannot create environment.\n");
        }
        if(create_db_conexion(&(data->db->tokensdb), (data->db->env), TOKENS_PATH ,DB_CREATE)!= DB_OK){
            wblprintf(LOG_CRITICAL,"SPAMHUNTING EVENTHANDLER","Cannot open tokens database\n");
        }

        if(create_db_dup_conexion(&(data->db->pairsdb), (data->db->env), PAIRS_PATH ,DB_CREATE)!= DB_OK){
            wblprintf(LOG_CRITICAL,"SPAMHUNTING EVENTHANDLER","Cannot open pairs database\n");
        }

        if(create_db_conexion(&(data->db->emaildb), (data->db->env), EMAIL_PATH ,DB_CREATE)!= DB_OK){
            wblprintf(LOG_CRITICAL,"SPAMHUNTING EVENTHANDLER","Cannot open email database\n");
        }
        else{
*/
            //hashmap_iterate_elements((map_t)_content,&print_info,NULL);
        databases *b=malloc(sizeof(databases));

        b->tokens=data->db->tokensdb;
        b->email=data->db->emaildb;
        (data->db->pairsdb)->cursor(data->db->pairsdb, NULL, &(data->db->cursor), 0);
        b->cursor=data->db->cursor;

        keys *k=malloc(sizeof(keys));
        char *message_id;
        char *body;

        if ((message_id=getHeaderContent((map_t)_content, "Message-ID"))==NULL){
            if ((message_id=getHeaderContent((map_t)_content, "Message-Id"))==NULL)
                message_id=getHeaderContent((map_t)_content, "Message-Id");
        }
        //printf("Message-ID%s\n",message_id);
        /*if (hashmap_get((map_t)_content,"Message-ID",(any_t *)&message_id)==MAP_MISSING){
             if(hashmap_get((map_t)_content,"Message-Id",(any_t *)&message_id)==MAP_MISSING){
                hashmap_get((map_t)_content,"Message-id",(any_t *)&message_id);
            }
        }*/
        ((char *)message_id==NULL)?
        (wblprintf(LOG_CRITICAL,"SPAMHUNTING PLUGIN","Message-Id is NULL")):
        (0);

        body=dump_text(_content);

        (body!=NULL)?((k->tokens)=tokenize(body)):((k->tokens)=NULL);

        //body=getHeaderContent((map_t)_content, "body");
        //printf("BODY %s\n",body);
        //body=dump_text(_content);
        //printf("BODY 2 %s\n",body);
        //hashmap_get((map_t)_content,"body",(any_t *)&body);

        k->message_id=malloc(sizeof(char)*strlen((char *)message_id)+1);
        strcpy(k->message_id,message_id);

        //k->tokens=tokenize(body);
        //hashmap_iterate_elements(k->tokens,&print_info,NULL);

        store_mail_sh(b,k,isspam);

        free_tokenize_sh(k);
        free(b);   

        (isspam==1)?
        (wblprintf(LOG_INFO,"SPAMHUNTING EVENTHANDLER","Trainning message as spam...\n")):
        (wblprintf(LOG_INFO,"SPAMHUNTING EVENTHANDLER","Trainning message as ham...\n"));

//        }
//    }        
}

static int start(void *d){
    
    sh_data *data=(sh_data *)d;
    cp_context_t *ctx;
    
    data->funcs=(function_t *)malloc(sizeof(function_t));
    data->funcs->function=&hunt_spam;
    data->funcs->conf_function=&set_sh_config;
    data->funcs->data=data;

    data->events=(eventhandler_t *)malloc(sizeof(eventhandler_t));
    data->events->function=&autolearn_spam_hunting;
    data->events->data=data;
    data->events->parser_name="full";
    ctx=data->ctx;

    //Dinamyc plugin initialization
    if ((cp_define_symbol(ctx, "es_uvigo_ei_hunt_spam", data->funcs)==CP_OK) &&
        (cp_define_symbol(ctx, "es_uvigo_ei_autolearn_spam_hunting", data->events)==CP_OK))
            return CP_OK;
    else
       return CP_ERR_RESOURCE;
}

int free_sh_cache(element elem){
    c_element cache_element=(c_element)elem;
    //printf("SACO DE LA CACHE: %s\n",cache_element->key);
    free(cache_element->data);
    free(cache_element->key);
    free(cache_element);
}

static void stop(void *d) {
/*
     sh_data *data=(struct sh_data *)d;
     
     if(data->db!=NULL){
        if(((data->db->cursor)->close((data->db->cursor)))!=0){
           wblprintf(LOG_WARNING,"SPAMHUNTING PLUGIN","Error closing cursor.\n");
        }
        if((close_db_conexion(&(data->db->tokensdb), TOKENS_PATH)!=DB_OK) ||
            (close_db_conexion(&(data->db->pairsdb), PAIRS_PATH)!=DB_OK)||
            (close_db_conexion(&(data->db->emaildb), EMAIL_PATH)!=DB_OK)){
                wblprintf(LOG_WARNING,"SPAMHUNTING PLUGIN","Error closing databases.\n");
        }
        if((data->db->env)->close((data->db->env),0)!=0){
            wblprintf(LOG_WARNING,"SPAMHUNTING PLUGIN","Error closing environment.\n");
        }
     }
     freeEMLParser();    
     free(data->db);
*/
     
}

static void destroy(void *d) {
    sh_data *data=(struct sh_data *)d;
    free_cache(data->cache,&free_sh_cache);
         
    if(((data->db->cursor)->close((data->db->cursor)))!=0){
        wblprintf(LOG_WARNING,"SPAMHUNTING PLUGIN","Error closing cursor.\n");
    }
    if((close_db_conexion(&(data->db->tokensdb), TOKENS_PATH)!=DB_OK) ||
        (close_db_conexion(&(data->db->pairsdb), PAIRS_PATH)!=DB_OK)||
        (close_db_conexion(&(data->db->emaildb), EMAIL_PATH)!=DB_OK)){
        wblprintf(LOG_WARNING,"SPAMHUNTING PLUGIN","Error closing databases.\n");
    }
    if((data->db->env)->close((data->db->env),0)!=0){
        wblprintf(LOG_WARNING,"SPAMHUNTING PLUGIN","Error closing environment.\n");
    }
    
    freeEMLParser(); 
    
    free(data->db);
     
    free(data->funcs);
    free(data->config);
    free(data->events);
    free(d);
}

CP_EXPORT cp_plugin_runtime_t spam_hunting_plugin_runtime_functions = {create, start, stop, destroy};