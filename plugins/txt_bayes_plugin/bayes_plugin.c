/***************************************************************************
*
*   File    : bayes_plugin.c
*   Purpose :
*
*
*   Author  : Noemí Pérez Díaz
*   Date    : February  16, 2011
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
#include "db_utils.h"
#include "parse_func_args.h"
#include "logger.h"
#include "bayes_util.h"
#include "learn_bayes_utils.h"
#include "learn_cms_bayes.h"

#define BAYES_OK 1
#define BAYES_FAIL 0


static void set_bayes_config(void *_data, ini_file *config_file);

static int check_bayes(void *_data, void *content, char *params, const char *flags){//, int parserType){
    bayes_data *data=(bayes_data *)_data;
    //char *email_key;
    char *key=NULL;
    short res=BAYES_FAIL;
    long double *result;
    float min,max;
    char *target_content=content;

    if(data->dbp==NULL){ 
        wblprintf(LOG_WARNING,"BAYES_PLUGIN","Cannot open database. Bayes computing aborted...\n");
        return res;
    }
    //printf("target_content: %s\n",target_content);

    //printf("CONTENIDO %s\n",target_content);
    
    if ((key=get_full_hash(target_content))==NULL){
        wblprintf(LOG_WARNING,"BAYES_PLUGIN","Cannot compute Message-ID\n");
        return res;
    }
        
    //strcpy(key,email_key);

    function_arguments *arguments=parse_args(params,2);
    if(get_argument_type(arguments,0)!=TYPE_FLOAT|| get_argument_type(arguments,1)!=TYPE_FLOAT){
        wblprintf(LOG_WARNING,"BAYES PLUGIN: ","Incorrect arguments %s\n", params);
        return res;
    }

    min=atof(get_argument_content(arguments,0));
    max=atof(get_argument_content(arguments,1));


    if(peek_cache(data->cache,key,(element *)&result)==CACHE_ELEM_MISSING){        
        result=(long double *)malloc(sizeof(long double));
        
        *result=scan_mail((char *)target_content,(data->dbp),data->config);
        push_cache(data->cache,key,&free_cache_data,(element)result);
    }else free(key);

    (*result>=min && *result<=max)?(res=BAYES_OK):(res=BAYES_FAIL);

    free_arguments(arguments);
    
    return res;
}

static void autolearn_bayes(void *_data, void *_content, const int isspam){
    
    bayes_data *data=(bayes_data *)_data;
    map_t tokens=cms_tokenizebody(_content);
    
    if(data->dbp==NULL){
        if(create_env(&(data->env),BAYES_ENV_PATH)!=DB_OK)
           wblprintf(LOG_CRITICAL,"BAYES EVENTHANDLER","Cannot create environment.\n");

        if(create_db_conexion(&(data->dbp), data->env, data->config->database_path,DB_CREATE)!=DB_OK)
           wblprintf(LOG_CRITICAL,"BAYES EVENTHANDLER","Cannot open database.\n");
           return;
    }

    if(isspam==1){
       store_mail(data->dbp,tokens,OPT_SPAM);
       wblprintf(LOG_INFO,"BAYES EVENTHANDLER","Trainning message as spam...\n");
    }else{
       //store_ham(data->dbp,_content);
       store_mail(data->dbp,tokens,OPT_HAM);
       wblprintf(LOG_INFO,"BAYES EVENTHANDLER","Trainning message as ham...\n");
    }
    free_tokenize(tokens);
}

static void *create(cp_context_t *ctx){//Abrir bd
    bayes_data *data;
   
    data=(bayes_data *)malloc(sizeof(bayes_data));
    data->config=malloc(sizeof(bayes_config));
    data->config->is_config_passed=NONE;
    
    data->cache=newcache(DEFAULT_CACHE_SIZE);
    data->dbp=NULL;
    data->ctx=ctx;
    
    //START
    
    data->funcs=(function_t *)malloc(sizeof(function_t));
    data->funcs->function=&check_bayes;
    data->funcs->data=data;
    data->funcs->conf_function=&set_bayes_config;

    data->events=(eventhandler_t *)malloc(sizeof(eventhandler_t));
    data->events->function=&autolearn_bayes;
    data->events->data=data;
    data->events->parser_name="txt";
    
    return data;
}

static int start(void *d){//LLamo a la funcion
    bayes_data *data=(bayes_data *)d;

    //Dinamyc plugin initialization
    if (cp_define_symbol(data->ctx, "es_uvigo_ei_check_bayes", data->funcs)==CP_OK &&
        cp_define_symbol(data->ctx, "es_uvigo_ei_autolearn_bayes", data->events)==CP_OK)
       return CP_OK;
    else return CP_ERR_RESOURCE;
}

static void set_bayes_config(void *_data, ini_file *config_file){
    bayes_data *data=(bayes_data *)_data;
    
    if(!data->config->is_config_passed){
    
        void *res;
    
        if(get_attribute_values_ini(config_file,"BAYES PLUGIN","min_nspam",(void **)&res)>0){
            data->config->min_nspam=atoi(res);
        }else data->config->min_nspam=DEFAULT_MIN_NSPAM;

        if(get_attribute_values_ini(config_file,"BAYES PLUGIN","min_nham",(void **)&res)>0){
            data->config->min_nham=atoi(res);
        }else data->config->min_nham=DEFAULT_MIN_NHAM;

        if(get_attribute_values_ini(config_file,"BAYES PLUGIN","cache_size",(void **)&res)>0){
            data->config->cache_size=atoi(res);
        }else data->config->cache_size=DEFAULT_CACHE_SIZE;

        if(get_attribute_values_ini(config_file,"BAYES PLUGIN","require_significant_tokens",(void **)&res)>0){
            data->config->require_significant_tokens=atoi(res);
        }else data->config->require_significant_tokens=DEFAULT_REQUIRE_SIGNIFFICANT_TOKENS_TO_SCORE;

        if(get_attribute_values_ini(config_file,"BAYES PLUGIN","database_path",(void **)&res)>0){
            data->config->database_path=res;
        }else data->config->database_path=DEFAULT_CMS_BAYES_DATABASE_PATH;

        if(get_cache_size(data->cache)!=data->config->cache_size)
           set_cache_size(data->cache,data->config->cache_size);

        if(data->dbp==NULL){
            if(create_env(&(data->env),BAYES_ENV_PATH)!=DB_OK){
                wblprintf(LOG_CRITICAL,"BAYES PLUGIN","Cannot create environment.\n");
            }
            if(create_db_conexion(&(data->dbp), data->env, data->config->database_path,DB_CREATE)!= DB_OK)
                wblprintf(LOG_CRITICAL,"BAYES PLUGIN","Cannot open database.\n");
        }
        data->config->is_config_passed=1;
    }else wblprintf(LOG_DEBUG,"BAYES PLUGIN","Configuration util already executed\n");
}

static void stop(void *d) {
     //bayes_data *data=(bayes_data *)d;
     //free_cache(data->cache,&free_bayes_cache);
     //free(data->funcs);
     //free(data->config);
     //if(data->dbp!=NULL){
     //   if((close_db_conexion(&(data->dbp), data->config->database_path))!=DB_OK){
     //       wblprintf(LOG_WARNING,"BAYES PLUGIN","Error closing databases.\n");
     //   }
     //   if((data->env)->close((data->env),0)!=0){
     //       wblprintf(LOG_WARNING,"BAYES PLUGIN","Error closing environment.\n");
     //   }
     //}
     //free(data->dbp);
    //printf("EXECUTING BAYES STOP PLUGIN\n");
}

static void destroy(void *d) {
    bayes_data *data=(bayes_data *)d;
    free_cache(data->cache,&free_bayes_cache);
    if(data->dbp!=NULL){
        if((close_db_conexion(&(data->dbp), data->config->database_path))!=DB_OK){
            wblprintf(LOG_WARNING,"BAYES PLUGIN","Error closing databases.\n");
        }
        if((data->env)->close((data->env),0)!=0){
            wblprintf(LOG_WARNING,"BAYES PLUGIN","Error closing environment.\n");
        }
    }
    free(data->funcs);
    free(data->config);
    free(data->events);
    free(d);
}

CP_EXPORT cp_plugin_runtime_t bayes_plugin_runtime_functions = {create, start, stop, destroy};