/***************************************************************************
*
*   File    : learn_bayes.c
*   Purpose : library for loading and storing email tokens in BDB
*
*
*   Original Author: David Ruano Ordás
*
*   Date    : January  4, 2011
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

/*---------------------------------------------------------------------------
   								INCLUDES
 ---------------------------------------------------------------------------*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "learn_bayes_utils.h"
#include "list_files.h"
#include "logger.h"
#include "tokenize.h"
#include "sha1.h"
#include "eml_parser.h"
#include "fileutils.h"



/*---------------------------------------------------------------------------
                                                                       MACROS
 ---------------------------------------------------------------------------*/

//#define DEFAULT_DB_PATH "bayes.db"
//#define DEFAULT_DUMP_OUTPUT_PATH "dump_bayes.dat"

/*---------------------------------------------------------------------------
                                                                  GLOBAL VARS
 ---------------------------------------------------------------------------*/

//char *DB_PATH=DEFAULT_DB_PATH;
//char *DUMP_FILE_PATH=DEFAULT_DUMP_OUTPUT_PATH;

/*---------------------------------------------------------------------------
                                                                    FUNCTIONS
 ---------------------------------------------------------------------------*/

/**
 * Assigns the path for storing bayes database.
 */
//void set_database_path(char *dbpath){
//    DB_PATH=dbpath;
//}

/**
 * Assigns the path for dump bayes database.
 */
//void set_dump_path(char *db_dump_path){
//    DUMP_FILE_PATH=db_dump_path;
//}

/**
 * Returns the path of bayes database.
 */
/*
char *get_database_path(){
    return DB_PATH;
}
*/

/**
 * Creates and opens a database conexion.
 */
/*
int create_db_conexion(DB **dbp, char *db_path, u_int32_t db_flags){
    
    //set_database_path(db_path);

    //Creates a DB structure.
    if(db_create(dbp,NULL,0)!=0){
        wblprintf(LOG_CRITICAL,"LEARN_BAYES","Could not create database\n");
        return DB_FAIL;
    }
    //Opens the database.
    if ((*dbp)->open(*dbp,NULL, db_path, NULL, DB_HASH, db_flags,0) !=0 ){
        wblprintf(LOG_CRITICAL,"LEARN_BAYES","Could not open database\n");
        return DB_FAIL;
    }
    return DB_OK;
}
*/

/**
 * Flushes any cached database information to disk, closes any open cursors,
 * frees any allocated resources, and closes any underlying files.
 */
/*
void close_db_conexion(DB **dbp, char *db_path){

    //set_database_path(db_path);

    if(*dbp!=NULL){
        wblprintf(LOG_DEBUG,"LEARN_BAYES","Closing Database in %s\n",DB_PATH);
        (*dbp)->close(*dbp,0);
        *dbp=NULL;
    }

}
*/

/**
 * Generates the hash of a string.
 */
/*
char *get_hash(char *token){
    
    SHA1Context sha;
    SHA1Reset(&sha);
    SHA1Input(&sha, (const unsigned char *)token, strlen(token));

    if (!SHA1Result(&sha))
        return NULL;
    char *hashkey=malloc(sizeof(unsigned)*10 +sizeof(char));
    sprintf(hashkey,"%X%X",sha.Message_Digest[3],sha.Message_Digest[4]);
    return hashkey;
}
*/

/**
 * Establishes the number of spam and ham messages that contains a token
 * and initializes its probability.
 * This information is recorded in a struct.
 */
void set_data_token(tokendata **tok,const int ham, const int spam){

    if(*tok==NULL)
       *tok=malloc(sizeof(tokendata));

    if(*tok==NULL){
        wblprintf(LOG_CRITICAL,"LEARN_BAYES","No enough memory\n");
        exit(1);
    }
    (*tok)->spam_count=spam;
    (*tok)->ham_count=ham;
    (*tok)->probability=0.0;
}

/**
 * Sets the probability of a token.
 */
void set_prob_token(tokendata **tok,const float prob){

    if(tok==NULL){
        wblprintf(LOG_CRITICAL,"LEARN_BAYES:","There is not a valid token\n");
        exit(1);
    }
    (*tok)->probability=prob;
}

/**
 * Returns a struct with the probability and the number of spam and ham messages of a token
 * stored in a database.
 */
int get_data_token(DB *dbp,char *token, tokendata *dat){

    char *hashkey = get_hash(token);

    if(hashkey==NULL){
        wblprintf(LOG_CRITICAL,"LEARN_BAYES","Could not compute message digest\n");
        return HASH_FAIL;
    }
    else{
        DBT key, data;

        memset(&key,0,sizeof(DBT));
        memset(&data,0,sizeof(DBT));

        key.data = hashkey;
        key.size = sizeof(char)*(strlen(hashkey)+1);

        /* Recovery the information of the token from the database. */
        if(dbp->get(dbp,NULL,&key,&data,0)==DB_NOTFOUND){
            free(hashkey);
            return TOKEN_MISSING;
        }
        else{
            memcpy(dat,(tokendata *)data.data,sizeof(tokendata));
            free(hashkey);
            return TOKEN_FOUND;
        }
    }

}

/**
 * Stores a struct with the number of spam and ham messages in a database.
 */
void store_magic_token(DB * dbp, int type){
    
    char *hashkey=get_hash(MAGIC_TOKEN);

    if (hashkey==NULL){
        wblprintf(LOG_CRITICAL,"LEARN_BAYES","Could not compute message digest\n");
        exit(1);
    }
    else{
        DBT key, data;
        
        memset(&key,0,sizeof(DBT));
        memset(&data,0,sizeof(DBT));

        /* The key is the hash of the empty word.*/
        key.data = hashkey;
        key.size = sizeof(char)*strlen(hashkey)+1;

        if(dbp->get(dbp,NULL,&key,&data,0)==DB_NOTFOUND){

            tokendata *dat=NULL;//malloc(sizeof(tokendata));
            (type==OPT_SPAM)?(set_data_token(&dat,0,1)):(set_data_token(&dat,1,0));

            data.data=dat;
            data.size=sizeof(tokendata);

            dbp->put(dbp, NULL, &key, &data, DB_NOOVERWRITE);
            free(dat);
        }
        else{
            (type==OPT_HAM)?(((tokendata *)data.data)->ham_count+=1):(((tokendata *)data.data)->spam_count+=1);

            dbp->del((DB *)dbp,NULL,&key,0);
            dbp->put((DB *)dbp,NULL,&key,&data,DB_NOOVERWRITE);

        }
    }
    free(hashkey);
}

/**
 * Stores the information of token contained in spam message.
 */
int store_spam(void *dbp, void *token){

    /* If the token is the empty word or count token it can't be stored.*/
    if(strcmp(token,INIT_TOKEN) && strcmp((char *)token,COUNT_TOKEN)){
        //printf("STORE_SPAM %s\n",(char *)token);
        char *hashkey=get_hash(token);

        if (hashkey==NULL){
            wblprintf(LOG_CRITICAL,"LEARN_BAYES","Could not compute message digest\n");
            return MAP_MISSING;
        }
        else{
            //printf("STORE_SPAM 2\n");
            DBT key, data;

            memset(&key,0,sizeof(DBT));
            memset(&data,0,sizeof(DBT));

            key.data = hashkey;
            key.size = sizeof(char)*strlen(hashkey)+1;

            //printf("STORE_SPAM 3\n");
            
            if(((DB *)dbp)->get((DB *)dbp,NULL,&key,&data,0)==DB_NOTFOUND){

                tokendata *dat=NULL;//malloc(sizeof(tokendata));

                /* Stores the token and initializes to one its number of spam messages
                   and to zero the number of ham messages*/
                set_data_token(&dat,0,1);
                data.data=dat;
                data.size=sizeof(tokendata);

                ((DB *)dbp)->put((DB* )dbp, NULL, &key, &data, DB_NOOVERWRITE);
                free(dat);
            }
            else{
                //printf("STORE_SPAM 4 - SI ESTA BD\n");
                /* Increases by one the number of spam messages.*/
                ((tokendata *)data.data)->spam_count+=1;

                ((DB *)dbp)->del((DB *)dbp,NULL,&key,0);
                ((DB *)dbp)->put((DB *)dbp,NULL,&key,&data,DB_NOOVERWRITE);

                wblprintf(LOG_DEBUG,"LEARN_BAYES","Word (%s) update\n",(char *)key.data);

            }
            free(hashkey);
        }
    }
    return MAP_OK;
}

/**
 * Stores the information of token contained in ham message.
 */
int store_ham(void *dbp, void *token){
    /* If the token is the empty word or count token it can't be stored.*/
    if(token!=NULL && strcmp(token,INIT_TOKEN)!=0 && 
                      strcmp((char *)token,COUNT_TOKEN)!=0){
        char *hashkey=get_hash(token);
    
        if (hashkey==NULL){
            wblprintf(LOG_CRITICAL,"LEARN_BAYES","Could not compute message digest\n");
            return MAP_MISSING;
        }
        else{
        
            DBT key, data;

            memset(&key,0,sizeof(DBT));
            memset(&data,0,sizeof(DBT));

            key.data = hashkey;
            key.size = sizeof(char)*strlen(hashkey)+1;

            if(((DB *)dbp)->get((DB *)dbp,NULL,&key,&data,0)==DB_NOTFOUND){
                tokendata *dat=NULL;

                /* Stores the token and initializes to one its number of ham messages
                   and to zero the number of spam messages*/
                set_data_token(&dat,1,0);

                data.data=dat;
                data.size=sizeof(tokendata);

                ((DB *)dbp)->put((DB *)dbp, NULL, &key, &data, DB_NOOVERWRITE);
                free(dat);
            }
            else{

                /* Increases by one the number of ham messages.*/
                ((tokendata *)data.data)->ham_count+=1;

                ((DB *)dbp)->del((DB *)dbp,NULL,&key,0);
                ((DB *)dbp)->put((DB *)dbp,NULL,&key,&data,DB_NOOVERWRITE);

                wblprintf(LOG_DEBUG,"LEARN_BAYES","Word (%s) update\n",(char *)key.data);

            }
            free(hashkey);
        }
    }
    return MAP_OK;
}

/**
 * Loads an email from a path.
 */

/*
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
*/

/**
 * Exports a berkeley database to a file.
 */
void db_dump(char *db_path,char *file_path){

    DB *dbp=NULL;
    DB_ENV *bayes_env;
    //u_int32_t db_flags;
    DBC *db_cursor;
    DBT key,data;
    FILE *file;

    if(create_env(&bayes_env,BAYES_LEARN_ENV_PATH)!=DB_OK){
        wblprintf(LOG_CRITICAL,"LEARN_BAYES","Could not create environment\n");
        exit(EXIT_FAILURE);
    }

    /* If the database can't be open.*/
    if(create_db_conexion(&dbp, bayes_env, db_path,  DB_CREATE)!=DB_OK){
        wblprintf(LOG_CRITICAL,"LEARN_BAYES","Could not open database\n");
        exit(EXIT_FAILURE);
    }
    /*
    if(db_create(&dbp,NULL,0)!=0){
        wblprintf(LOG_CRITICAL,"LEARN_BAYES","Could not create database\n");
        exit(1);
    }

    db_flags= DB_CREATE;

    if (dbp->open(dbp,NULL, db_path, NULL, DB_HASH, db_flags,0) !=0 ){
        wblprintf(LOG_CRITICAL,"LEARN_BAYES","Could not open database\n");
        exit(1);
    }
    */
    dbp->cursor(dbp,NULL,&db_cursor,0);

    memset(&key,0,sizeof(DBT));
    memset(&data,0,sizeof(DBT));

    file = fopen(file_path,"wb");

    if(file==NULL){
        wblprintf(LOG_CRITICAL,"LEARN_BAYES","File not open\n");
        exit(1);
    }
    int i=0;
    /* For each token is stored its number of spam and ham messages and its probability.*/
    while (db_cursor->get(db_cursor,&key,&data,DB_NEXT)==0){
        printf("  KEY %s\n",(char *)key.data);
        printf("  SPAM: %ld\n",((tokendata *)data.data)->spam_count);
        printf("  HAM: %ld\n",((tokendata *)data.data)->ham_count);
        printf("  Probability: %2.2f\n\n",((tokendata *)data.data)->probability);
        fwrite(((char *)key.data),sizeof(char)*16,1,file);
        fwrite(((tokendata *)data.data),sizeof(tokendata),1,file);
        i++;
    }

    if(fclose(file)!=0){
        wblprintf(LOG_CRITICAL,"LEARN_BAYES","Could not close file\n");
        exit(1);
    }

    if(db_cursor!=NULL)
        db_cursor->c_close(db_cursor);

    if(dbp!=NULL)
        close_db_conexion(&dbp, db_path);
    
    bayes_env->close(bayes_env,0);

    wblprintf(LOG_INFO,"LEARN_BAYES","Total %d records saved\n\t\t\t\t\t       Export succesfully completed\n",i);
    
}

/**
 * Imports a berkeley database from a file.
 */
void db_load(char *file_path, char *db_path){
    
    DB *dbp=NULL;
    DB_ENV *bayes_env;
    //u_int32_t db_flags;
    DBT key,data;
    FILE *file;

    file = fopen(file_path,"rb");

    if(file==NULL){
        wblprintf(LOG_CRITICAL,"LEARN_BAYES","Could not open. File %s does not exist\n",file_path);
        exit(1);
    }
    
    if(create_env(&bayes_env,BAYES_LEARN_ENV_PATH)!=DB_OK){
        wblprintf(LOG_CRITICAL,"LEARN_BAYES","Could not create environment\n");
        exit(EXIT_FAILURE);
    }

    /* If the database can't be open.*/
    if(create_db_conexion(&dbp, bayes_env, db_path,  DB_CREATE)!=DB_OK){
        wblprintf(LOG_CRITICAL,"LEARN_BAYES","Could not open database\n");
        exit(EXIT_FAILURE);
    }
    
    memset(&key,0,sizeof(DBT));
    memset(&data,0,sizeof(DBT));

    /* Stores each token and its information in a berkeley database.*/
    tokendata *token=malloc(sizeof(tokendata));
    char *tokenkey=malloc(sizeof(char)*17);
    int i=0;
    
    while(fread(tokenkey,sizeof(char),16,file)){
        if(fread(token,sizeof(tokendata),1,file)!=sizeof(tokendata))
            wblprintf(LOG_CRITICAL,"LEARN_BAYES","Error reading token from file\n");
        
        tokenkey[16]='\0';
        
        key.data = tokenkey;
        key.size = (sizeof(char)*(strlen(tokenkey)+1));

        data.data= token;
        data.size= sizeof(tokendata);

        printf("Inserting token\n");
        printf("  KEY %s\n",(char *)key.data);
        printf("  SPAM: %ld\n",((tokendata *)data.data)->spam_count);
        printf("  HAM: %ld\n",((tokendata *)data.data)->ham_count);
        
        dbp->put(dbp, NULL, &key, &data, DB_NOOVERWRITE);
        i++;
    }
    free(token);
    free(tokenkey);
    fclose(file);

    wblprintf(LOG_INFO,"LEARN_BAYES","Total %d records saved\n\t\t\t\t\t       Import succesfully completed\n",i);

    if(dbp!=NULL){
        wblprintf(LOG_DEBUG,"Closing Database in %s\n",db_path);
            close_db_conexion(&dbp, db_path);
    }
    bayes_env->close(bayes_env,0);
    

}

void db_print(char *db_path){

    DB *dbp=NULL;
    DB_ENV *bayes_env;
    //u_int32_t db_flags;
    DBC *db_cursor;
    DBT key,data;

    if(create_env(&bayes_env,BAYES_LEARN_ENV_PATH)!=DB_OK){
        wblprintf(LOG_CRITICAL,"LEARN_BAYES","Could not create environment\n");
        exit(EXIT_FAILURE);
    }

    /* If the database can't be open.*/
    if(create_db_conexion(&dbp, bayes_env, db_path,  DB_CREATE)!=DB_OK){
        wblprintf(LOG_CRITICAL,"LEARN_BAYES","Could not open database\n");
        exit(EXIT_FAILURE);
    }
    /*
    if(db_create(&dbp,NULL,0)!=0){
        wblprintf(LOG_CRITICAL,"LEARN_BAYES","Could not create database\n");
        exit(1);
    }

    db_flags= DB_CREATE;

    if (dbp->open(dbp,NULL, db_path, NULL, DB_HASH, db_flags,0) !=0 ){
        wblprintf(LOG_CRITICAL,"LEARN_BAYES","Could not open database\n");
        exit(1);
    }
    */
    dbp->cursor(dbp,NULL,&db_cursor,0);

    memset(&key,0,sizeof(DBT));
    memset(&data,0,sizeof(DBT));

    long i=0;
    /* For each token is stored its number of spam and ham messages and its probability.*/
    while (db_cursor->get(db_cursor,&key,&data,DB_NEXT)==0){
        printf("  KEY %s\n",(char *)key.data);
        printf("  SPAM: %ld\n",((tokendata *)data.data)->spam_count);
        printf("  HAM: %ld\n",((tokendata *)data.data)->ham_count);
        printf("  Probability: %2.2f\n\n",((tokendata *)data.data)->probability);
        i++;
    }

    (db_cursor!=NULL)?(db_cursor->c_close(db_cursor)):(1);

    (dbp!=NULL)?(close_db_conexion(&dbp, db_path)):(1);
    bayes_env->close(bayes_env,0);

    wblprintf(LOG_INFO,"LEARN_BAYES","Total %l records\n",i);

}

/**
 * Stores the tokens of an e-mail in a berkeley database.
 */
void store_mail(DB *dbp,map_t tokens,short type){

    if(type==OPT_HAM){
        hashmap_iterate_keys(tokens,&store_ham,dbp);
        store_magic_token(dbp,OPT_HAM);
    }
    else{
        hashmap_iterate_keys(tokens,&store_spam,dbp);
        store_magic_token(dbp,OPT_SPAM);
    }

}