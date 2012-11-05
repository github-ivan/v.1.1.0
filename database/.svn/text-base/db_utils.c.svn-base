/* 
 * File:   db_utils.c
 * Author: drordas
 *
 * Created on 20 de septiembre de 2011, 14:16
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "logger.h"
#include "sha1.h"
#include "db_utils.h"
#include "fileutils.h"

int create_env(DB_ENV **env, char *env_path){
    //Added for concurrent mode.
    int ret;
    if ((ret=db_env_create(env, 0))!=0){
        wblprintf(LOG_CRITICAL,"DB_UTILS","Could not create database environment\n");
        return DB_FAIL;
    }
    (*env)->set_flags(*env,DB_INIT_CDB,ret);
    if ((ret= (*env)->open(*env, env_path, DB_CREATE | DB_INIT_MPOOL, 0))!=0){
        wblprintf(LOG_CRITICAL,"DB_UTILS","Could not open database environment\n");
        return DB_FAIL;
    }
    return DB_OK;
}

int create_db_conexion(DB **dbp, DB_ENV *env, char *db_path, u_int32_t db_flags){

    /*Creates a DB structure.*/
    if(*dbp!=NULL){
        wblprintf(LOG_DEBUG,"DB_UTILS","DB already open\n");
        return DB_OK;    
    }
    
    if(db_create(dbp,env,0)!=0){
        wblprintf(LOG_CRITICAL,"DB_UTILS","Could not create database\n");
        return DB_FAIL;
    }
    /*Opens the database.*/
    if ((*dbp)->open(*dbp,NULL, db_path, NULL, DB_HASH, db_flags,0) !=0 ){
        wblprintf(LOG_CRITICAL,"DB_UTILS","Could not open database\n");
        return DB_FAIL;
    }
    return DB_OK;
}

char *loademail(char *path){

    char *content;
    
    if(ae_load_eml_to_memory(path, &content)>0){
        wblprintf(LOG_DEBUG,"LEARN_BAYES","Email loaded succesfully\n");
        return content;
    }else{
        wblprintf(LOG_CRITICAL,"LEARN_BAYES","File not found\n");
        exit(1);
    }
}

int create_db_dup_conexion(DB **dbp, DB_ENV *env, char *db_path, u_int32_t db_flags){

    if(*dbp!=NULL){
        wblprintf(LOG_DEBUG,"DB_UTILS","DB already open\n");
        return DB_OK;    
    }
    /*Creates a DB structure.*/
    if(db_create(dbp, env, 0)!=0){
        wblprintf(LOG_CRITICAL,"LEARN_SPAMHUNTING","Could not create database\n");
        return DB_FAIL;
    }
    /*Opens the database.*/
    (*dbp)->set_flags(*dbp,DB_DUP);
    if ((*dbp)->open(*dbp,NULL, db_path, NULL, DB_HASH, db_flags,0) !=0 ){
        wblprintf(LOG_CRITICAL,"LEARN_SPAMHUNTING","Could not open database\n");
        return DB_FAIL;
    }
    return DB_OK;
}

int close_db_conexion(DB **dbp, char *db_path){

    if(*dbp!=NULL){
        wblprintf(LOG_DEBUG,"DB_UTILS","Closing Database in %s\n",db_path);
        if((*dbp)->close(*dbp,0)!=0){
            wblprintf(LOG_CRITICAL,"DB_UTILS","Could not close database\n");
            *dbp=NULL;
            return DB_FAIL;
        }
        *dbp=NULL;
        return DB_OK;
    }
    else return DB_FAIL;
}



char *get_hash(char *token){
    
    SHA1Context sha;
    SHA1Reset(&sha);
    SHA1Input(&sha, (const unsigned char *)token, strlen(token));

    if (!SHA1Result(&sha)) return NULL;
    
    char *hashkey=malloc(sizeof(unsigned)*10 +sizeof(char));
    sprintf(hashkey,"%X%X",sha.Message_Digest[3],sha.Message_Digest[4]);
    return hashkey;
}

char *get_full_hash(char *text){
    
    SHA1Context sha;
    SHA1Reset(&sha);
    SHA1Input(&sha, (const unsigned char *)text, strlen(text));

    if (!SHA1Result(&sha)) return NULL;
    
    char *hashkey=malloc(sizeof(unsigned)*25+sizeof(char));
    sprintf(hashkey,"%X%X%X%X%X",sha.Message_Digest[0],sha.Message_Digest[1],
            sha.Message_Digest[2],sha.Message_Digest[3],sha.Message_Digest[4]);
    return hashkey;
}

