/* 
 * File:   learn_cms_bayes.c
 * Author: drordas
 *
 * Created on 5 de marzo de 2012, 17:21
 */

#include <stdio.h>
#include <stdlib.h>
#include "db_utils.h"
#include "list_files.h"
#include "logger.h"
#include "tokenize.h"
#include "eml_parser.h"
#include "learn_bayes_utils.h"

#define BAYES_SPAM_LEARN_ENV_PATH "."


/**
 * Stores in a hashmap the tokens of an e-mail body.
 */
map_t tokenizebody(char *email){
    char *res;
    
    rfc2822eml ret= parser_mail(email);
    map_t tokenmap;
    
    //printf("before dump_text\n");
    res=dump_text(ret);
    //printf("after dum_text\n");
    
    (res!=NULL)?(tokenmap=tokenize(res)):(tokenmap=NULL);
    
    //free(res);
    free_mail(ret);
    //freeEMLParser();
    
    return tokenmap;
}

/**
 * Loads the emails contained in a path and stores its tokens in a berkeley database.
 */
void load_directory_mail(char *directory, char *db_path, int type){

    filelist *mails_directory=list_files(directory,"eml");
    int i=0;
    DB *dbp=NULL;
    DB_ENV *bayes_env;
    map_t tokenbody;
    char *email;
    int count=0;

    //bayes_env=malloc(sizeof(DB_ENV *));
    /* If the path is incorrect. */
    if(mails_directory==NULL){
        wblprintf(LOG_CRITICAL,"LEARN_BAYES","Directory not found");
        exit(EXIT_FAILURE);
    }

    /* If the directory not contains any e-mail.*/
    if (count_files_filelist(mails_directory)==0){
        wblprintf(LOG_CRITICAL,"LEARN_BAYES","Directory empty\n");
        exit(EXIT_FAILURE);
    }

    /*If the environment can't be created.*/
    if(create_env(&bayes_env,BAYES_SPAM_LEARN_ENV_PATH)!=DB_OK){
        wblprintf(LOG_CRITICAL,"LEARN_BAYES","Could not create environment\n");
        exit(EXIT_FAILURE);
    }

    /* If the database can't be open.*/
    if(create_db_conexion(&dbp, bayes_env, db_path,  DB_CREATE)!=DB_OK){
        wblprintf(LOG_CRITICAL,"LEARN_BAYES","Could not open database\n");
        exit(EXIT_FAILURE);
    }

    /*If the e-mail is a spam message, its tokens will be stored in the database as spam tokens.*/
    if(type==OPT_SPAM)
        for(;i<count_files_filelist(mails_directory);i++){
            wblprintf(LOG_INFO,"LEARN_BAYES","Spam file name: %s\n",get_file_at(mails_directory,i));
            email=loademail(get_file_at(mails_directory,i));
            if((tokenbody=tokenizebody(email))!=NULL){
                count++;
                store_mail(dbp,tokenbody,OPT_SPAM);
                free_tokenize(tokenbody);
            }
            else{}
            free(email);
    }/*If the e-mail is a ham message, its tokens will be stored in the database as ham tokens.*/
    else
        for(;i<count_files_filelist(mails_directory);i++){
            wblprintf(LOG_INFO,"LEARN_BAYES","Ham file name: %s\n",get_file_at(mails_directory,i));
            email=loademail(get_file_at(mails_directory,i));
            if((tokenbody=tokenizebody(email))!=NULL){
                count++;
                store_mail(dbp,tokenbody,OPT_HAM);
                free_tokenize(tokenbody);
            }
            free(email);
        }
    free_filelist(mails_directory);
    close_db_conexion(&dbp, db_path);
    bayes_env->close(bayes_env,0);
    //free(bayes_env);
    freeEMLParser();
    printf("Summary %d messages\n",i);
    printf("  %d messages inserted\n",count);
    printf("  %d messages wrong\n",i-count);
}

