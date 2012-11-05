/***************************************************************************
*
*   File    : learn_cmshunting.c
*   Purpose : library for loading and storing in spamhunting's BDBs
*
*
*   Original Author: Noemí Pérez Díaz
*
*   Date    : March 17, 2011
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
#include "learn_spamhunting.h"
#include "list_files.h"
#include "logger.h"
#include "tokenize.h"
#include "linked_list.h"
#include "sha1.h"
#include "eml_parser.h"
#include "fileutils.h"
#include "string_util.h"
#include "db_utils.h"

/*---------------------------------------------------------------------------
                                                                       MACROS
 ---------------------------------------------------------------------------*/

#define TOKENS_DB_PATH "wb4spam_tokens.db"
#define EMAIL_DB_PATH "wb4spam_email.db"
#define PAIRS_DB_PATH "wb4spam_pairs.db"

#define DEFAULT_TOKENS_PATH "wb4spam_tokens.dat"
#define DEFAULT_EMAIL_PATH "wb4spam_email.dat"
#define DEFAULT_PAIRS_PATH "wb4spam_pairs.dat"

#define SH_LEARN_ENV_PATH "."

/*---------------------------------------------------------------------------
                                                                  GLOBAL VARS
 ---------------------------------------------------------------------------*/

char *DB_PATH_TOKENS=TOKENS_DB_PATH;
char *DB_PATH_EMAIL=EMAIL_DB_PATH;
char *DB_PATH_PAIRS=PAIRS_DB_PATH;

char *DUMP_TOKENS_PATH=NULL;
char *DUMP_EMAIL_PATH=NULL;
char *DUMP_PAIRS_PATH=NULL;

char *LOAD_TOKENS_PATH=NULL;
char *LOAD_EMAIL_PATH=NULL;
char *LOAD_PAIRS_PATH=NULL;

/*---------------------------------------------------------------------------
                                                                   DATA TYPES
 ---------------------------------------------------------------------------*/


/*---------------------------------------------------------------------------
                                                                    FUNCTIONS
 ---------------------------------------------------------------------------*/

/*
 * --------------------GENERAL FUNCTIONS FOR DATABASES-------------------------
*/

/**
 * Assigns the path for dump spamhunting databases.
 */
void set_dump_path_sh(char *out_path){

    DUMP_TOKENS_PATH=malloc(sizeof(char)*(strlen(out_path)+11));
    sprintf(DUMP_TOKENS_PATH,"%s%s",out_path,DEFAULT_TOKENS_PATH);
    
    DUMP_EMAIL_PATH=malloc(sizeof(char)*(strlen(out_path)+11));
    sprintf(DUMP_EMAIL_PATH,"%s%s",out_path,DEFAULT_EMAIL_PATH);

    DUMP_PAIRS_PATH=malloc(sizeof(char)*(strlen(out_path)+11));
    sprintf(DUMP_PAIRS_PATH,"%s%s",out_path,DEFAULT_PAIRS_PATH);
   
}

/**
 * Assigns the path for load spamhunting databases.
 */
void set_load_path_sh(char *load_path){

    LOAD_TOKENS_PATH=malloc(sizeof(char)*(strlen(load_path)+11));
    sprintf(LOAD_TOKENS_PATH,"%s%s",load_path,DEFAULT_TOKENS_PATH);
   
    LOAD_EMAIL_PATH=malloc(sizeof(char)*(strlen(load_path)+11));
    sprintf(LOAD_EMAIL_PATH,"%s%s",load_path,DEFAULT_EMAIL_PATH);

    LOAD_PAIRS_PATH=malloc(sizeof(char)*(strlen(load_path)+11));
    sprintf(LOAD_PAIRS_PATH,"%s%s",load_path,DEFAULT_PAIRS_PATH);
}

/**
 * Assigns the path for tokens database.
 */
void set_tokens_database_path(char *tokenspath){
    DB_PATH_TOKENS=tokenspath;
}

/**
 * Assigns the path for email database.
 */
void set_email__database_path(char *emailpath){
    DB_PATH_EMAIL=emailpath;
}

/**
 * Assigns the path for pairs database.
 */
void set_pairs_database_path(char *pairspath){
    DB_PATH_PAIRS=pairspath;
}

/**
 * Returns the tokens database path.
 */
char *get_tokens_database_path(){
    return DB_PATH_TOKENS;
}

/**
 * Returns the email database path.
 */
char *get_email_database_path(){
    return DB_PATH_EMAIL;
}

/**
 * Returns the pairs database path.
 */
char *get_pairs_database_path(){
    return DB_PATH_PAIRS;
}

/*
 * --------------------FUNCTIONS FOR TOKENS DATABASE-----------------------------
 * Key: token
 * Data: number of spam messages and ham messages of this token (tokensdata)
*/

/**
 * Establishes the number of spam and ham messages that contains a token
 * This information is recorded in a struct.
 */
void set_data_token_sh(tokensdata **tok,const int ham, const int spam){

    if(*tok==NULL)
       *tok=malloc(sizeof(tokensdata));

    if(*tok==NULL){
        wblprintf(LOG_CRITICAL,"LEARN_SPAMHUNTING","No enough memory\n");
        exit(1);
    }
    (*tok)->spam_count=spam;
    (*tok)->ham_count=ham;
}

/**
 * Returns a struct with the number of spam and ham messages of a token
 * stored in tokens database.
 */
int get_data_token_sh(DB *dbp,char *token, tokensdata *dat){

    char *hashkey = get_hash(token);

    if(hashkey==NULL){
        wblprintf(LOG_CRITICAL,"LEARN_SPAMHUNTING","Could not compute message digest\n");
        return HASH_FAIL;
    }
    else{
        DBT key, data;

        memset(&key,0,sizeof(DBT));
        memset(&data,0,sizeof(DBT));

        key.data = hashkey;
        key.size = sizeof(char)*(strlen(hashkey)+1);

        if(dbp->get(dbp,NULL,&key,&data,0)==DB_NOTFOUND){
            free(hashkey);
            return TOKEN_MISSING;
        }
        else{
            memcpy(dat,(tokensdata *)data.data,sizeof(tokensdata));
            free(hashkey);
            return TOKEN_FOUND;
        }
    }
}

/**
 * Stores a struct with the number of spam and ham messages in tokens database.
 */
void store_magic_token_sh(DB *dbp, int type){

    char *hashkey=get_hash(MAGIC_TOKEN);

    if (hashkey==NULL){
        wblprintf(LOG_CRITICAL,"LEARN_SPAMHUNTING","Could not compute message digest\n");
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

            tokensdata *dat=NULL;
            if(type==OPT_SPAM)
                set_data_token_sh(&dat,0,1);
            else
                set_data_token_sh(&dat,1,0);

            data.data=dat;
            data.size=sizeof(tokensdata);

            dbp->put(dbp, NULL, &key, &data, DB_NOOVERWRITE);
            free(dat);
        }
        else{
            if(type==OPT_HAM)
                ((tokensdata *)data.data)->ham_count+=1;
            else
                ((tokensdata *)data.data)->spam_count+=1;

            dbp->del((DB *)dbp,NULL,&key,0);
            dbp->put((DB *)dbp,NULL,&key,&data,DB_NOOVERWRITE);
        }
    }
    free(hashkey);
}

/*
 * --------------------FUNCTIONS FOR PAIRS DATABASE-----------------------------
 * Key: token
 * Data: Message id of the e-mail that contains the token.
 * Comments: Allows duplicates.
*/

/**
 * Compare two elements.
 */
int compare_pairs (element a, element b){
    if (strcmp((char *)a,(char *)b)<0){
        return -1;
    }
    else if (strcmp((char *)a,(char *)b)>0)
            return 1;
         else return 0;
}
/*
int print(any_t item,any_t data, any_t key){
    printf("KEY: %s\n",(char *)key);
    printf("VALUE: %d\n",*(int *)data);
    return MAP_OK;
}
*/
/**
 * Returns a linked list with the message id of a token.
 */
int get_data_pairs_sh(DB *dbp,char *token, linkedhashmap **pairslist){

    char *hashkey = get_hash(token);

    if(hashkey==NULL){
        wblprintf(LOG_CRITICAL,"LEARN_SPAMHUNTING","Could not compute message digest\n");                  
        return HASH_FAIL;
    }
    else{
        DBT key, data;

        memset(&key,0,sizeof(DBT));
        memset(&data,0,sizeof(DBT));

        key.data = hashkey;
        key.size = sizeof(char)*(strlen(hashkey)+1);

        DBC *cursor;
        int ret;
        dbp->cursor(dbp, NULL, &cursor,0 );

        if((ret=cursor->c_get(cursor,&key,&data,DB_SET))==DB_NOTFOUND){
            free(hashkey);
            return TOKEN_MISSING;
        }
        else{
            //ret=cursor->c_get(cursor,&key,&data,DB_SET)
            while (ret==0 /*&& !strcmp((char *)key.data,hashkey)*/)
            {
                //printf("DATO introducido en la lista %s\n",(char *)data.data);
                //printf("ENCONTRANDO EMAILS DEL TOKEN\n");
                //printf("TOKEN %s\n",(char *)key.data);
                //printf("EMAIL %s\n",(char *)data.data);
                //addorder(*pairslist,&data.data,&compare_pairs);
                any_t elem;
                //hashmap_iterate_elements(lh_gethashmap(*pairslist),&print,NULL);
                if(get_lh_element(*pairslist,(char *)data.data,(any_t *)&elem)==LH_MISSING){
                    //int *data=malloc(sizeof(int));
                    //*data=1;
                    //char * aux=malloc(sizeof(char)*strlen(data.data)+1);
                    //strcpy(aux,data.data);
                    messageoccur *msgoc=malloc(sizeof(messageoccur));
                    //msgoc->message_id=aux;
                    msgoc->message_id=malloc(sizeof(char)*strlen(data.data)+1);
                    strcpy(msgoc->message_id,data.data);
                    msgoc->occurrences=1;
                    //printf("Añadiendo nuevo email: %s\n",(char *)data.data);
                    //printf("AÑADIENDO EMAIL: %s\n",(char *)data.data);
                    //printf("\t KEY_EMAIL: %s\n",msgoc->message_id);
                    //printf("\t OCCURS_TOKEN_EMAIL: %d\n",msgoc->occurrences);
                    //printf("ADD NO EXISTE %d\n",add_lh_element(*pairslist,(char *)data.data,msgoc));
                    add_lh_element(*pairslist,msgoc->message_id,msgoc);
                }
                else{
                    //int *data=malloc(sizeof(int));
                    //*data++;
                    messageoccur *msgoc=(messageoccur *)elem;
                    msgoc->occurrences++;
                    //printf("sumando occur al email: %s\n",(char *)data.data);
                    //printf("EXISTE EMAIL: %s\n",(char *)data.data);
                    //printf("\t KEY_EMAIL: %s\n",msgoc->message_id);
                    //printf("\t OCCURS_TOKEN_EMAIL: %d\n",msgoc->occurrences);
                    //printf("ADD LH EXIST %d\n",add_lh_element(*pairslist,(char *)data.data,msgoc));
                    //add_lh_element(*pairslist,(char *)data.data,msgoc);
                }
                //printf("PROXIMA KEY REPETIDA %d\n",ret=cursor->c_get(cursor,&key,&data,DB_NEXT));
                ret=cursor->c_get(cursor,&key,&data,DB_NEXT_DUP);
                //printf("next_key: %s\n",key.data);
            }
            free(hashkey); //DAVID
            return TOKEN_FOUND;
        }
    }
}

int get_data_email_sh(DB *dbp,char *email, int *class){

    if(email==NULL){
        wblprintf(LOG_CRITICAL,"LEARN_SPAMHUNTING","Could not compute message digest\n");
        return HASH_FAIL;
    }
    else{
        DBT key, data;
        
        memset(&key,0,sizeof(DBT));
        memset(&data,0,sizeof(DBT));

        key.data = email;
        key.size = sizeof(char)*(strlen(email)+1);

        if(dbp->get(dbp,NULL,&key,&data,0)==DB_NOTFOUND){
            return TOKEN_MISSING;
        }
        else{
            memcpy(class,(int *)data.data,sizeof(int));
            return TOKEN_FOUND;
        }
    }
}

/*
 * --------------------------MAIN FUNCTIONS------------------------------------
*/

/**
 * Stores the information of spam message.
 */
int store_spam_sh(void *dbs, void *message_id, void *token){

    /* If a message token is the empty word or count token it can't be stored.*/
    if(strcmp(token,INIT_TOKEN) && strcmp((char *)token,COUNT_TOKEN)){
        char *hashkey=get_hash(token);

        if (hashkey==NULL){
            wblprintf(LOG_CRITICAL,"LEARN_SPAMHUNTING","Could not compute message digest\n");
            return MAP_MISSING;
        }
        else{
            DB *tokens_dbp = (DB *)((databases *)dbs)->tokens;
            DB *email_dbp = (DB *)((databases *)dbs)->email;
            //DB *pairs_dbp = (DB *)((databases *)dbs)->pairs;
            DBC *cursor= (DBC *)((databases *)dbs)->cursor;

            DBT key, data;

            memset(&key,0,sizeof(DBT));
            memset(&data,0,sizeof(DBT));

            key.data = hashkey;
            key.size = sizeof(char)*strlen(hashkey)+1;
            //printf("Token %s\n",(char *)token);
            /* Stores a token in token database with its number of ham and spam messages.*/
            if(((DB *)tokens_dbp)->get((DB *)tokens_dbp,NULL,&key,&data,0)==DB_NOTFOUND){
                tokensdata *dat=NULL;
                set_data_token_sh(&dat,0,1);
                data.data=dat;
                data.size=sizeof(tokensdata);
                //printf("INTRODUCE TOKEN %i\n",((tokensdata *)data.data)->ham_count);
                ((DB *)tokens_dbp)->put((DB *)tokens_dbp, NULL, &key, &data, DB_NOOVERWRITE);
                free(dat);
            }
            else{
                ((tokensdata *)data.data)->spam_count+=1;
                //printf("INTRODUCE TOKEN %i\n",((tokensdata *)data.data)->ham_count);
                ((DB *)tokens_dbp)->del((DB *)tokens_dbp,NULL,&key,0);
                ((DB *)tokens_dbp)->put((DB *)tokens_dbp,NULL,&key,&data,DB_NOOVERWRITE);

                wblprintf(LOG_DEBUG,"LEARN_SPAMHUNTING","Word (%s) update\n",(char *)key.data);

            }

            //EMAIL BD!!!!!!!!!!!!!!
            char *hashemail=get_hash(message_id);

            if (hashemail==NULL){
                wblprintf(LOG_CRITICAL,"LEARN_SPAMHUNTING","Could not compute message digest\n");
                return MAP_MISSING;
            }
            else{
                //PAIRS DB:SOPORTA DUPLICADOS
                data.data = hashemail;
                data.size = sizeof(char)*strlen(hashemail)+1;
                //printf("PAIRS DB\n");
                //printf("MESSAGE-ID %s\n",(char *)data.data);
                //printf("TOKEN-ID %s\n",(char *)key.data);
                /* Stores a token with its message id in pairs database.*/
                cursor->put(cursor, &key, &data, DB_KEYLAST);

                key.data = hashemail;
                key.size = sizeof(char)*strlen(hashemail)+1;
                int *class;
                class=malloc(sizeof(int));
                *class=1;
                /* Stores in email database the message id and its class.*/
                if(((DB *)email_dbp)->get((DB *)email_dbp,NULL,&key,&data,0)==DB_NOTFOUND){
                    data.data=class;
                    data.size=sizeof(int);
                    //printf("CLASE %i\n",*(int *)data.data);
                    //printf("INTRODUCE EMAIL");
                    ((DB *)email_dbp)->put((DB* )email_dbp, NULL, &key, &data, DB_NOOVERWRITE);
                }else{
                    data.data=class;
                    data.size=sizeof(int);
                    //printf("CLASE %i\n",*(int *)data.data);
                    ((DB *)email_dbp)->del((DB *)email_dbp,NULL,&key,0);
                    ((DB *)email_dbp)->put((DB* )email_dbp, NULL, &key, &data, DB_NOOVERWRITE);
                    wblprintf(LOG_DEBUG,"LEARN_SPAMHUNTING","Email (%s) update\n",(char *)key.data);
                }
                free(class);
            }
            free(hashemail);
        }
        free(hashkey);
    }
    return MAP_OK;
}

/**
 * Stores the information of ham message.
 */
int store_ham_sh(void *dbs, void *message_id, void *token){

    /* If a message token is the empty word or count token it can't be stored.*/
    if(strcmp(token,INIT_TOKEN) && strcmp((char *)token,COUNT_TOKEN)){
        char *hashkey=get_hash(token);

        if (hashkey==NULL){
            wblprintf(LOG_CRITICAL,"LEARN_SPAMHUNTING","Could not compute message digest\n");
            return MAP_MISSING;
        }
        else{
            DB *tokens_dbp = (DB *)((databases *)dbs)->tokens;
            DB *email_dbp = (DB *)((databases *)dbs)->email;
            //DB *pairs_dbp = (DB *)((databases *)dbs)->pairs;
            DBC *cursor= (DBC *)((databases *)dbs)->cursor;

            DBT key, data;

            memset(&key,0,sizeof(DBT));
            memset(&data,0,sizeof(DBT));
            //TOKENS DB
            key.data = hashkey;
            key.size = sizeof(char)*strlen(hashkey)+1;
            //printf("ANtes if. Token %s\n",(char *)token);
            
            /* Stores a token in token database with its number of ham and spam messages.*/
            if(((DB *)tokens_dbp)->get((DB *)tokens_dbp,NULL,&key,&data,0)==DB_NOTFOUND){
                tokensdata *dat=NULL;
                set_data_token_sh(&dat,1,0);
                data.data=dat;
                data.size=sizeof(tokensdata);
                //printf("NUEVO:INTRODUCE TOKEN %s\n",(char *)key.data);
                ((DB *)tokens_dbp)->put((DB *)tokens_dbp, NULL, &key, &data, DB_NOOVERWRITE);
                free(dat);
            }
            else{
                ((tokensdata *)data.data)->ham_count+=1;
                //printf("REPETIDO:INTRODUCE TOKEN %s\n",(char *)key.data);
                ((DB *)tokens_dbp)->del((DB *)tokens_dbp,NULL,&key,0);
                ((DB *)tokens_dbp)->put((DB *)tokens_dbp,NULL,&key,&data,DB_NOOVERWRITE);

                wblprintf(LOG_DEBUG,"LEARN_SPAMHUNTING","Word (%s) update\n",(char *)key.data);
            }

            //EMAIL DB
            char *hashemail=get_hash(message_id);

            if (hashemail==NULL){
                wblprintf(LOG_CRITICAL,"LEARN_SPAMHUNTING","Could not compute message digest\n");
                return MAP_MISSING;
            }
            else{
                //PAIRS DB:SOPORTA DUPLICADOS
                data.data = hashemail;
                data.size = sizeof(char)*strlen(hashemail)+1;
                //printf("MESSAGE-ID %s\n",(char *)data.data);
                /* Stores a token with its message id in pairs database.*/
                //printf("PAIRS DB\n");
                //printf("MESSAGE-ID %s\n",(char *)data.data);
                //printf("TOKEN-ID %s\n",(char *)key.data);
                cursor->c_put(cursor, &key, &data, DB_KEYLAST);

                key.data = hashemail;
                key.size = sizeof(char)*strlen(hashemail)+1;
                int *class;
                class=malloc(sizeof(int));
                *class=0;
                /* Stores in email database the message id and its class.*/
                if(((DB *)email_dbp)->get((DB *)email_dbp,NULL,&key,&data,0)==DB_NOTFOUND){
                    data.data=class;
                    data.size=sizeof(int);
                    //printf("CLASE %i\n",*(int *)class);
                    ((DB *)email_dbp)->put((DB* )email_dbp, NULL, &key, &data, DB_NOOVERWRITE);
                }else{
                    data.data=class;
                    data.size=sizeof(int);
                    //printf("CLASE %i\n",*(int *)class);
                    ((DB *)email_dbp)->del((DB *)email_dbp,NULL,&key,0);
                    ((DB *)email_dbp)->put((DB* )email_dbp, NULL, &key, &data, DB_NOOVERWRITE);
                    wblprintf(LOG_DEBUG,"LEARN_SPAMHUNTING","Email (%s) update\n",(char *)key.data);
                }
                free(class);
            }
            free(hashemail);
        }
        free(hashkey);
    }
    return MAP_OK;
}



void free_tokenize_sh(keys *_key){
    if(_key!=NULL){
        free(_key->message_id);
        free_tokenize(_key->tokens);
        free(_key);
    }
}

/**
 * Stores in a hashmap the tokens of an e-mail body.
 */
keys *tokenize_sh(char *email){
    keys *k=malloc(sizeof(keys));

    char *res;
    char *id;

    rfc2822eml ret= parser_mail(email);
    map_t tokenmap;
    res=dump_text(ret);
    
    (res!=NULL)?(tokenmap=tokenize(res)):(tokenmap=NULL);
    
    if (hashmap_get(ret,"Message-ID",(any_t *)&id)==MAP_MISSING){
        if(hashmap_get(ret,"Message-Id",(any_t *)&id)==MAP_MISSING){
            hashmap_get(ret,"Message-id",(any_t *)&id);
        }
    }

    if ((char *)id==NULL){
        wblprintf(LOG_CRITICAL,"LEARN_SPAMHUNTING: ","Message-Id is NULL");
        return NULL;
    }
    k->tokens=tokenmap;
    //printf("ID %s\n",(char *)id);
    k->message_id=malloc(sizeof(char)*strlen(id)+1);
    strcpy(k->message_id,id);
    
    //free(res);
    free_mail(ret);
    //freeEMLParser();
    
    return k;
}

/**
 * Stores the information of an e-mail in three berkeley databases.
 */
void store_mail_sh(databases *dbs, keys *k,short type){

    if(type==OPT_HAM){
        hashmap_iterate_three(k->tokens,&store_ham_sh,k->message_id,dbs);
        store_magic_token_sh(dbs->tokens,OPT_HAM);
    }else{
        hashmap_iterate_three(k->tokens,&store_spam_sh,k->message_id,dbs);
        store_magic_token_sh(dbs->tokens,OPT_SPAM);
    }
}

/**
 * Loads the emails contained in a path and stores its information in three databases.
 */
void load_directory_mail_sh(char *directory, int type){

    filelist *mails_directory=list_files(directory,"eml");
    int i=0;
    DB *tokens_dbp=NULL;
    DB *email_dbp=NULL;
    DB *pairs_dbp=NULL;
    DB_ENV *env;
    
    DBC *cursor;

    keys *k;
    char *email;
    int count=0;

    /* If the path is incorrect. */
    if(mails_directory==NULL){
        wblprintf(LOG_CRITICAL,"LEARN_SPAMHUNTING","Directory not found");
        exit(EXIT_FAILURE);
    } 

    /* If the directory not contains any e-mail.*/
    if (count_files_filelist(mails_directory)==0){
        wblprintf(LOG_CRITICAL,"LEARN_SPAMHUNTING","Directory empty\n");
        exit(EXIT_FAILURE);
    }

    //env=malloc(sizeof(DB_ENV *));
    /* If the environment can't be created.*/
    if(create_env(&env,SH_LEARN_ENV_PATH)!=DB_OK){
        wblprintf(LOG_CRITICAL,"LEARN_SPAMHUNTING","Could not open databases\n");
        exit(EXIT_FAILURE);
    }
    /* If the databases can't be open.*/
    if((create_db_conexion(&tokens_dbp, env, DB_PATH_TOKENS, DB_CREATE)!=DB_OK) ||
       (create_db_conexion(&email_dbp, env, DB_PATH_EMAIL, DB_CREATE)!=DB_OK) ||
       (create_db_dup_conexion(&pairs_dbp, env, DB_PATH_PAIRS, DB_CREATE)!=DB_OK)){
        wblprintf(LOG_CRITICAL,"LEARN_SPAMHUNTING","Could not open databases\n");
        exit(EXIT_FAILURE);
    }
  
    databases *b=malloc(sizeof(databases));
    b->tokens=tokens_dbp;
    b->email=email_dbp;
    //b->pairs=pairs_dbp;
    pairs_dbp->cursor(pairs_dbp, NULL, &cursor, 0);
    b->cursor=cursor;

    /*If the e-mail is a spam message.*/
    if(type==OPT_SPAM)
        for(;i<count_files_filelist(mails_directory);i++){
            wblprintf(LOG_INFO,"LEARN_SPAMHUNTING","File name: %s\n",get_file_at(mails_directory,i));
            email=loademail(get_file_at(mails_directory,i));
            k=tokenize_sh(email);   
            if(k!=NULL){
                count++;
                store_mail_sh(b,k,OPT_SPAM);
                //free_tokenize(k->tokens);
                free_tokenize_sh(k);
            }else wblprintf(LOG_CRITICAL,"LEARN_SPAMHUNTING","Error processing email\n");
            free(email);
        }
    /*If the e-mail is a ham message.*/
    else
        for(;i<count_files_filelist(mails_directory);i++){
            wblprintf(LOG_INFO,"LEARN_SPAMHUNTING","File name: %s\n",get_file_at(mails_directory,i));
            email=loademail(get_file_at(mails_directory,i));
            k=tokenize_sh(email);
            if(k!=NULL) {
                count++;
                store_mail_sh(b,k,OPT_HAM);
                //free_tokenize(k->tokens);
                free_tokenize_sh(k);
            }
            else wblprintf(LOG_CRITICAL,"LEARN_SPAMHUNTING","Error processing email\n");
            free(email);
        }

    free_filelist(mails_directory);
    cursor->close(cursor);
    close_db_conexion(&tokens_dbp, DB_PATH_TOKENS);
    close_db_conexion(&email_dbp, DB_PATH_EMAIL);
    close_db_conexion(&pairs_dbp, DB_PATH_PAIRS);
    env->close(env,0);
    free(b);
    freeEMLParser();
    printf("Summary %d messages\n",i);
    printf("  %d messages inserted\n",count);
    printf("  %d messages wrong\n",i-count);
}

/**
 * Free memory used by a path.
 */
void free_path(char *path){
    if (path!=NULL)
        free(path);
}

/**
 * Exports tokens database to a file.
 */
void db_dump_tokens(char *db_path){

    DB_ENV *env;
    DB *dbp=NULL;
    DBC *db_cursor;
    DBT key,data;
    FILE *file;

    if(create_env(&env,SH_LEARN_ENV_PATH)!=DB_OK){
        wblprintf(LOG_CRITICAL,"LEARN_SPAMHUNTING","Could not open databases\n");
        exit(EXIT_FAILURE);
    }
    /* If the databases can't be open.*/
    if(create_db_conexion(&dbp, env, db_path, DB_CREATE)!=DB_OK){
        wblprintf(LOG_CRITICAL,"LEARN_SPAMHUNTING","Could not open databases\n");
        exit(EXIT_FAILURE);
    }
    dbp->cursor(dbp,NULL,&db_cursor,0);

    memset(&key,0,sizeof(DBT));
    memset(&data,0,sizeof(DBT));

    if(DUMP_TOKENS_PATH==NULL)
        file = fopen(DEFAULT_TOKENS_PATH,"wb");
    else
        file = fopen(DUMP_TOKENS_PATH,"wb");

    if(file==NULL){
        wblprintf(LOG_CRITICAL,"LEARN_SPAMHUNTING","File not open\n");
        exit(1);
    }
    int i=0;
    /* For each token is stored its number of spam and ham messages.*/
    while (db_cursor->get(db_cursor,&key,&data,DB_NEXT)==0){
        //printf("  KEY %s\n",(char *)key.data);
        //printf("  SPAM: %d\n",((tokensdata *)data.data)->spam_count);
        //printf("  HAM: %d\n",((tokensdata *)data.data)->ham_count);
        //printf("DATA");
        fwrite(((char *)key.data),sizeof(char)*16,1,file);
        fwrite(((tokensdata *)data.data),sizeof(tokensdata),1,file);
        i++;
        //printf("I %i\n",i);
    }

    if(fclose(file)!=0){
        wblprintf(LOG_CRITICAL,"LEARN_SPAMHUNTING","Could not close file\n");
        exit(1);
    }

    if(db_cursor!=NULL) db_cursor->close(db_cursor);

    if(dbp!=NULL) close_db_conexion(&dbp, db_path);
    if (env!=NULL) env->close(env,0);
    
    free_path(DUMP_TOKENS_PATH);
    wblprintf(LOG_INFO,"LEARN_SPAMHUNTING","[DB: Tokens] Total %d records saved\n\t\t\t\t\t       Export succesfully completed\n",i);
}

/**
 * Imports tokens database from a file.
 */
void db_load_tokens(){

    DB_ENV *env;
    DB *dbp=NULL;
    DBT key,data;
    FILE *file;

    if(LOAD_TOKENS_PATH==NULL)
        file = fopen(DEFAULT_TOKENS_PATH,"rb");
    else
        file = fopen(LOAD_TOKENS_PATH,"rb");
    
    if(file==NULL){
        wblprintf(LOG_CRITICAL,"LEARN_SPAMHUNTING","Could not open. File %s does not exist\n",LOAD_TOKENS_PATH);
        exit(1);
    }
    if(create_env(&env,SH_LEARN_ENV_PATH)!=DB_OK){
        wblprintf(LOG_CRITICAL,"LEARN_SPAMHUNTING","Could not open databases\n");
        exit(EXIT_FAILURE);
    }
    //If the databases can't be open.
    if(create_db_conexion(&dbp, env, TOKENS_DB_PATH, DB_CREATE)!=DB_OK){
        wblprintf(LOG_CRITICAL,"LEARN_SPAMHUNTING","Could not open databases\n");
        exit(EXIT_FAILURE);
    }

    memset(&key,0,sizeof(DBT));
    memset(&data,0,sizeof(DBT));

    tokensdata *token=malloc(sizeof(tokensdata));
    char *tokenkey=malloc((sizeof(char))*17);
    int i=0;
    size_t size=sizeof(tokensdata);

    while(fread(tokenkey,sizeof(char),16,file)){
        if(fread(token,sizeof(tokensdata),1,file)!=size){
            //printf("TOKENKEY %s\n",tokenkey);
            //printf("TOKEN %d\n",(tokensdata *)token->spam_count);
            //printf("TOKEN %d\n",(tokensdata *)token->ham_count);
           wblprintf(LOG_CRITICAL,"LEARN_SPAMHUNTING","Error reading token from file\n");
        }
        tokenkey[16]='\0';
        //printf("TOKENKEY %s\n",tokenkey);
        //printf("TOKEN %d\n",(tokensdata *)token->spam_count);
        //printf("TOKEN %d\n",(tokensdata *)token->ham_count);
            
        key.data = tokenkey;
        key.size = (sizeof(char)*(strlen(tokenkey)+1));

        data.data= token;
        data.size= sizeof(tokensdata);
        //printf("LOAD TOKENS KEY %s\n",(char *)key.data);
        //printf("LOAD TOKENS  SPAM: %d\n",((tokensdata *)data.data)->spam_count);
        //printf("LOAD TOKENS  HAM: %d\n",((tokensdata *)data.data)->ham_count);
        dbp->put(dbp, NULL, &key, &data, DB_NOOVERWRITE);
        i++;
    }

    free(token);
    free(tokenkey);
    fclose(file);

    wblprintf(LOG_INFO,"LEARN_SPAMHUNTING","Total %d records saved\n\t\t\t\t\t       Import succesfully completed\n",i);

    if(dbp!=NULL){
        wblprintf(LOG_DEBUG,"Closing Database in %s\n",DB_PATH_TOKENS);
        close_db_conexion(&dbp, TOKENS_DB_PATH);
    
      }
    env->close(env,0);
    free_path(LOAD_TOKENS_PATH);
}

/**
 * Exports email database to a file.
 */
void db_dump_email(char *db_path){

    DB_ENV *env;
    DB *dbp=NULL;
    DBC *db_cursor;
    DBT key,data;
    FILE *file;

    if(create_env(&env,SH_LEARN_ENV_PATH)!=DB_OK){
        wblprintf(LOG_CRITICAL,"LEARN_SPAMHUNTING","Could not open databases\n");
        exit(EXIT_FAILURE);
    }
    /* If the databases can't be open.*/
    if(create_db_conexion(&dbp, env, db_path, DB_CREATE)!=DB_OK){
        wblprintf(LOG_CRITICAL,"LEARN_SPAMHUNTING","Could not open databases\n");
        exit(EXIT_FAILURE);
    }

    dbp->cursor(dbp,NULL,&db_cursor,0);

    memset(&key,0,sizeof(DBT));
    memset(&data,0,sizeof(DBT));

    if(DUMP_EMAIL_PATH==NULL)
        file = fopen(DEFAULT_EMAIL_PATH,"wb");
    else
        file = fopen(DUMP_EMAIL_PATH,"wb");

    if(file==NULL){
        wblprintf(LOG_CRITICAL,"LEARN_SPAMHUNTING","File not open\n");
        exit(1);
    }
    int i=0;
    /* For each message-id is stored its class.*/
    while (db_cursor->get(db_cursor,&key,&data,DB_NEXT)==0){
        //printf("  KEY %s\n",(char *)key.data);
        //printf("  CLASS: %i\n",*(int *)data.data);
        fwrite(((char *)key.data),sizeof(char)*16,1,file);
        fwrite(((int *)data.data),sizeof(int),1,file);
        i++;
        //printf("I %i\n",i);
    }

    if(fclose(file)!=0){
        wblprintf(LOG_CRITICAL,"LEARN_SPAMHUNTING","Could not close file\n");
        exit(1);
    }

    if(db_cursor!=NULL)
        db_cursor->close(db_cursor);

    if(dbp!=NULL) close_db_conexion(&dbp, db_path);
    env->close(env,0);
    free_path(DUMP_EMAIL_PATH);
    wblprintf(LOG_INFO,"LEARN_SPAMHUNTING","[DB: Email] Total %d records saved\n\t\t\t\t\t       Export succesfully completed\n",i);
}

/**
 * Imports email database from a file.
 */
void db_load_email(char *file_path){

    DB_ENV *env;
    DB *dbp=NULL;
    DBT key,data;
    FILE *file;
    
    if(create_env(&env,SH_LEARN_ENV_PATH)!=DB_OK){
        wblprintf(LOG_CRITICAL,"LEARN_SPAMHUNTING","Could not open databases\n");
        exit(EXIT_FAILURE);
    }
    /* If the databases can't be open.*/
    if(create_db_conexion(&dbp, env, EMAIL_DB_PATH, DB_CREATE)!=DB_OK){
        wblprintf(LOG_CRITICAL,"LEARN_SPAMHUNTING","Could not open databases\n");
        exit(EXIT_FAILURE);
    }
    
    if(LOAD_EMAIL_PATH==NULL)
        file = fopen(DEFAULT_EMAIL_PATH,"rb");
    else
        file = fopen(LOAD_EMAIL_PATH,"rb");

    if(file==NULL){
        wblprintf(LOG_CRITICAL,"LEARN_SPAMHUNTING","Could not open. File %s does not exist\n",file_path);
        exit(1);
    }
    
    memset(&key,0,sizeof(DBT));
    memset(&data,0,sizeof(DBT));

    int *class=malloc(sizeof(int));
    char *email=malloc(sizeof(char)*16);
    int i=0;
    size_t size=sizeof(class);

    while(fread(email,sizeof(char)*16,1,file)){
        if(fread(class,sizeof(int),1,file)!=size)
                wblprintf(LOG_CRITICAL,"LEARN_SPAMHUNTING","Error reading class from file\n");
        //printf("Email %s\n",email);
        //printf("Class %i\n",*class);
        key.data = email;
        key.size = (sizeof(char)*(strlen(email)+1));

        data.data= class;
        data.size= sizeof(class);
        //printf("LOAD_EMAIL KEY-----> %s\n",(char *)key.data);
        //printf("LOAD_EMAIL CLASS-----> %d\n",*(int *)data.data);
        dbp->put(dbp, NULL, &key, &data, DB_NOOVERWRITE);
        i++;

    }
    free(email);
    free(class);
    fclose(file);

    wblprintf(LOG_INFO,"LEARN_SPAMHUNTING","Total %d records saved\n\t\t\t\t\t       Import succesfully completed\n",i);

    if(dbp!=NULL){
        wblprintf(LOG_DEBUG,"Closing Database in %s\n",DB_PATH_EMAIL);
        close_db_conexion(&dbp, EMAIL_DB_PATH);
    }
    if (env!=NULL) env->close(env,0);
    free_path(LOAD_EMAIL_PATH);
}

/**
 * Exports pairs database to a file.
 */
void db_dump_pairs(char *db_path){

    DB_ENV *env;
    DB *dbp=NULL;
    DBC *db_cursor;
    DBT key,data;
    FILE *file;

    if(create_env(&env,SH_LEARN_ENV_PATH)!=DB_OK){
        wblprintf(LOG_CRITICAL,"LEARN_SPAMHUNTING","Could not open databases\n");
        exit(EXIT_FAILURE);
    }
    /* If the databases can't be open.*/
    if(create_db_dup_conexion(&dbp, env, db_path, DB_CREATE)!=DB_OK){
        wblprintf(LOG_CRITICAL,"LEARN_SPAMHUNTING","Could not open databases\n");
        exit(EXIT_FAILURE);
    }

    dbp->cursor(dbp,NULL,&db_cursor,0);

    memset(&key,0,sizeof(DBT));
    memset(&data,0,sizeof(DBT));
    
    if(DUMP_PAIRS_PATH==NULL)
        file = fopen(DEFAULT_PAIRS_PATH,"wb");
    else
        file = fopen(DUMP_PAIRS_PATH,"wb");

    if(file==NULL){
        wblprintf(LOG_CRITICAL,"LEARN_SPAMHUNTING","File not open\n");
        exit(1);
    }
    int i=0;
   
    /* For each token is stored gets its message-id.*/
    while (db_cursor->get(db_cursor,&key,&data,DB_PREV)==0){
        //printf("  KEY %s\n",(char *)key.data);
        //printf("  MESSAGE-ID: %s\n",(char *)data.data);
        fwrite(((char *)key.data),sizeof(char)*16,1,file);
        fwrite(((char *)data.data),sizeof(char)*16,1,file);        
        i++;
    }

    if(fclose(file)!=0){
        wblprintf(LOG_CRITICAL,"LEARN_SPAMHUNTING","Could not close file\n");
        exit(1);
    }

    if(db_cursor!=NULL)
        db_cursor->close(db_cursor);

    if(dbp!=NULL)
        close_db_conexion(&dbp, db_path);
    env->close(env,0);
    free_path(DUMP_PAIRS_PATH);
    wblprintf(LOG_INFO,"LEARN_SPAMHUNTING","[DB:Pairs] Total %d records saved\n\t\t\t\t\t       Export succesfully completed\n",i);
}

/**
 * Imports pairs database from a file.
 */
void db_load_pairs(char *file_path){

    DB_ENV *env;
    DB *dbp=NULL;
    DBT key,data;
    FILE *file;

    if(LOAD_PAIRS_PATH==NULL)
        file = fopen(DEFAULT_PAIRS_PATH,"rb");
    else
        file = fopen(LOAD_PAIRS_PATH,"rb");
   
    if(file==NULL){
        wblprintf(LOG_CRITICAL,"LEARN_SPAMHUNTING","Could not open. File %s does not exist\n",file_path);
        exit(1);
    }
    
    if(create_env(&env,SH_LEARN_ENV_PATH)!=DB_OK){
        wblprintf(LOG_CRITICAL,"LEARN_SPAMHUNTING","Could not open databases\n");
        exit(EXIT_FAILURE);
    }
    /* If the databases can't be open.*/
    if(create_db_dup_conexion(&dbp, env, PAIRS_DB_PATH, DB_CREATE)!=DB_OK){
        wblprintf(LOG_CRITICAL,"LEARN_SPAMHUNTING","Could not open databases\n");
        exit(EXIT_FAILURE);
    }

    memset(&key,0,sizeof(DBT));
    memset(&data,0,sizeof(DBT));


    char *email=malloc(sizeof(char)*16);
    char *tokenkey=malloc(sizeof(char)*16);
    int i=0;
    size_t size=sizeof(email);

    while(fread(tokenkey,sizeof(char)*16,1,file)){
        if(fread(email,sizeof(char)*16,1,file)!=size)
            wblprintf(LOG_CRITICAL,"LEARN_SPAMHUNTING","Error reading token from file\n");
        //printf("tokenkey %s\n",tokenkey);
        //printf("email %s\n",email);
        key.data = tokenkey;
        key.size = (sizeof(char)*(strlen(tokenkey)+1));

        data.data= email;
        data.size= sizeof(email);
        //printf("LOAD_PAIRS KEY-----> %s\n",(char *)key.data);
        //printf("LOAD_PAIRS MESSAGE-ID-----> %s\n",(char *)data.data);
        dbp->put(dbp, NULL, &key, &data, DB_NOOVERWRITE);
        i++;
    }

    free(email);
    free(tokenkey);
    fclose(file);

    wblprintf(LOG_INFO,"LEARN_SPAMHUNTING","Total %d records saved\n\t\t\t\t\t       Import succesfully completed\n",i);

    if(dbp!=NULL){
        wblprintf(LOG_DEBUG,"Closing Database in %s\n",DB_PATH_PAIRS);
        close_db_conexion(&dbp, PAIRS_DB_PATH);
    }
    env->close(env,0);
    free_path(LOAD_PAIRS_PATH);
}