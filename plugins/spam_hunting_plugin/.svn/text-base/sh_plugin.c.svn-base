/* 
 * File:   sh_plugin.c
 * Author: david
 *
 * Created on 23 de junio de 2011, 13:20
 */

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <db.h>
#include <cpluff.h>
#include "learn_spamhunting.h"
#include "logger.h"
#include "hashmap.h"
#include "tokenize.h"
#include "linked_list.h"
#include "linkedhashmap.h"

#define DEFAULT_CACHE_SIZE 5

struct sh_data{
  //info *sh_info;
  //cache_data *cache;
  function_t *funcs;
  cp_context_t *ctx;
};

typedef struct sh_data sh_data;

static void *create(cp_context_t *ctx){//Abrir bd
    sh_data *retval;

    retval=(sh_data *)malloc(sizeof(sh_data));
    retval->ctx=ctx;
    return retval;
}

static int start(void *d){//LLamo a la funcion
    sh_data *data=(sh_data *)d;
    cp_context_t *ctx;
    
    //data->config=malloc(sizeof(bayes_config));
    data->funcs=(function_t *)malloc(sizeof(function_t));
    data->funcs->function=&hunt_spam;
    ctx=data->ctx;

    //Dinamyc plugin initialization
    if (cp_define_symbol(ctx, "es_uvigo_ei_hunt_spam", data->funcs)==CP_OK)
       return CP_OK;
    else
       return CP_ERR_RESOURCE;
}

static int hunt_spam(void *_data, void *content, char *params, const char *flags){
    //sh_data *data=(sh_data *)_data;
    //char *target_content=dump_text(content);
    //int result=scan_sh(target_content,data->sh_info);
    //printf("RESULTADO ES: %d\n",result);
    printf("EXECUTING SPAM_HUNTING\n");
    return 1;
    //return result;
}

static void stop(void *d) {
     sh_data *data=(sh_data *)d;
     free_cache(data->cache,&free_sh_cache);
     free(data->funcs);
     printf("FALTA CERRAR LAS BD\n");
     //if(close_db_conexion(&(data->sh_info), db_path)!=DB_OK)
     //   wblprintf(LOG_WARNING,"SpamHunting","Error closing database\n");
}

static void destroy(void *d) {
    free(d);
}

CP_EXPORT cp_plugin_runtime_t spam_hunting_plugin_runtime_functions = {create, start, stop, destroy};