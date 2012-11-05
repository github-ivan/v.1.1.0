/* 
 * File:   learn_awl.c
 * Author: drordas
 *
 * Created on 19 de septiembre de 2011, 17:22
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "learn_axl.h"
#include "header_parser.h"
#include "logger.h"
#include "fileutils.h"

#define BEGIN_LINE -1
#define END_LINE -2
#define BEGIN_COMMENT -3
#define END_COMMENT -4
#define NONE -5
#define AXL_LEARN_ENV_PATH "."

struct axl_info{
    long int spam;
    long int ham;
};

int get_axl_data(DB *dbp,char *content, axl_info **axl_data){    
    
    DBT key, data;

    memset(&key,0,sizeof(DBT));
    memset(&data,0,sizeof(DBT));

    key.data = content;
    key.size = sizeof(char)*(strlen(content)+1);
    /* Recovery the information of the token from the database. */
    if(dbp->get(dbp,NULL,&key,&data,0)==DB_NOTFOUND){
        *axl_data=NULL;
        return TOKEN_MISSING;    
    }
    else{
        if(*axl_data==NULL) *axl_data=malloc(sizeof(axl_info));
        memcpy(*axl_data,(axl_info *)data.data,sizeof(axl_info));
        return TOKEN_FOUND;
    }
}

void add_axl_data(DB *dbp,char *content, short isspam){    
    
    DBT key, data;

    memset(&key,0,sizeof(DBT));
    memset(&data,0,sizeof(DBT));

    key.data = content;
    key.size = sizeof(char)*(strlen(content)+1);
    
    if(dbp->get(dbp,NULL,&key,&data,0)==DB_NOTFOUND){
        axl_info *axl_data=(axl_info *)malloc(sizeof(axl_info));        
        if(isspam==SPAM){
            axl_data->spam=1;
            axl_data->ham=0;
        }else{
            axl_data->spam=0;
            axl_data->ham=1;
        }
        
        data.data=axl_data;
        data.size=sizeof(axl_info);        
        dbp->put(dbp, NULL, &key, &data, DB_NOOVERWRITE);
        free_axl_data(axl_data);
    }
    else{
        if(isspam==SPAM) ((axl_info *)data.data)->spam+=1;
        else ((axl_info *)data.data)->ham+=1;
        dbp->del((DB *)dbp,NULL,&key,0);
        dbp->put((DB *)dbp,NULL,&key,&data,DB_NOOVERWRITE);
    }
}

short get_axl_ham(axl_info *axl_data){
    if(axl_data==NULL) return -1;
    else return axl_data->ham;
}

short get_axl_spam(axl_info *axl_data){
    if(axl_data==NULL) return -1;
    else return axl_data->spam;
}

void free_axl_data(axl_info *axl_data){
    if(axl_data!=NULL) free(axl_data);
}

void load_axl_file(char *file_path, char *db_path){

    DB *dbp=NULL;
    DB_ENV *axl_env;
    char *text=NULL;
    char *start_pointer=NULL;
    int count=0, status=NONE, num_records=0, num_dup=0;
    char *begin=NULL;
    char *end=NULL;
    char *ip=NULL, *line=NULL, *domain=NULL;
    char *axl_entry=NULL;
    char *isspam=NULL;
    int spam;
    axl_info *axl_data;
    
    DBT key, data;
    /* If the path is incorrect. */
    
    if(ae_load_eml_to_memory(file_path,&text)<=0){
        wblprintf(LOG_CRITICAL,"LEARN_AXL","Could not open file %s\n",file_path);
        exit(EXIT_FAILURE);
    }
    
    start_pointer=text;

    //axl_env=malloc(sizeof(DB_ENV *));

    /*If the environment can't be created.*/
    if(create_env(&axl_env,AXL_LEARN_ENV_PATH)!=DB_OK){
        wblprintf(LOG_CRITICAL,"LEARN_AXL","Could not create environment\n");
        exit(EXIT_FAILURE);
    }
    /* If the database can't be open.*/
    if(create_db_conexion(&dbp, axl_env, db_path, DB_CREATE)!=DB_OK){
        wblprintf(LOG_CRITICAL,"LEARN_AXL","Could not open database\n");
        exit(EXIT_FAILURE);
    }
    while(start_pointer[count]!='\0'){
        if(start_pointer[count]!='\n' && status!=BEGIN_LINE){
            status=BEGIN_LINE;
            begin=&start_pointer[count];
            count++;
        }
        if(start_pointer[count]!='\n' && status==BEGIN_LINE) count++;
        if(start_pointer[count]=='\n' && status==BEGIN_LINE){
            end=&start_pointer[count];
            line=malloc(sizeof(char)*(end-begin+1));
            memcpy(line,begin,(end-begin)*sizeof(char));
            status=END_LINE;
            //printf("[+] %s\n",line);
            ip= strtok(line," \t");
            domain = strtok(NULL," \t");
            isspam = strtok(NULL," \t");
            spam = atoi(isspam);
            axl_entry=malloc(sizeof(char)*(strlen(ip)+strlen(domain)+2));
            sprintf(axl_entry,"%s@%s",ip,domain);
            
            memset(&key,0,sizeof(DBT));
            memset(&data,0,sizeof(DBT));
            
            key.data = axl_entry;
            key.size = sizeof(char)*strlen(axl_entry)+1;
            
            if(dbp->get(dbp,NULL,&key,&data,0)==DB_NOTFOUND){
                axl_data=malloc(sizeof(axl_info));
                if(spam){
                    axl_data->spam=1;
                    axl_data->ham=0;
                }else{
                    axl_data->spam=0;
                    axl_data->ham=1;
                }
                data.data=axl_data;
                data.size=sizeof(axl_info);
                dbp->put(dbp, NULL, &key, &data, DB_NOOVERWRITE);
                free(axl_data);
            }else{
                (spam)?(((axl_info *)data.data)->spam+=1):(((axl_info *)data.data)->ham+=1);
                num_dup++;
                dbp->put((DB *)dbp,NULL,&key,&data,0);
            }
            free(line);
            free(axl_entry);
            
            count++;
            num_records++;
        }
    }
    printf("Summary: %d changes made in axl database\n",num_records);
    printf("  [%d] updated\n", num_dup);
    printf("  [%d] added\n", (num_records-num_dup));
    close_db_conexion(&dbp, db_path);
    axl_env->close(axl_env,0);
    free(text);
    //printf("  %d messages inserted\n",num_records);    
}

void axl_print(char *db_path){
    DB *dbp=NULL;
    DB_ENV *axl_env;
    //u_int32_t db_flags;
    DBC *db_cursor;
    DBT key,data;

    if(create_env(&axl_env,AXL_LEARN_ENV_PATH)!=DB_OK){
        wblprintf(LOG_CRITICAL,"LEARN_AXL","Could not create environment\n");
        exit(EXIT_FAILURE);
    }
    /* If the database can't be open.*/
    if(create_db_conexion(&dbp, axl_env, db_path, DB_CREATE)!=DB_OK){
        wblprintf(LOG_CRITICAL,"LEARN_AXL","Could not open database\n");
        exit(EXIT_FAILURE);
    }
    /*
    if(db_create(&dbp,NULL,0)!=0){
        wblprintf(LOG_CRITICAL,"LEARN_AXL","Could not create database\n");
        exit(1);
    }

    db_flags= DB_CREATE;

    if (dbp->open(dbp,NULL, db_path, NULL, DB_HASH, db_flags,0) !=0 ){
        wblprintf(LOG_CRITICAL,"LEARN_AXL","Could not open database\n");
        exit(1);
    }
    */
    dbp->cursor(dbp,NULL,&db_cursor,0);

    memset(&key,0,sizeof(DBT));
    memset(&data,0,sizeof(DBT));

    int i=0;
    /* For each token is stored its number of spam and ham messages and its probability.*/
    while (db_cursor->get(db_cursor,&key,&data,DB_NEXT)==0){
        printf(" RECORD [%d]\n",i+1);
        printf(" -KEY: %s\n",(char *)key.data);
        printf(" -SPAM: %ld\n",((axl_info *)data.data)->spam);
        printf(" -HAM: %ld\n",((axl_info *)data.data)->ham);
        i++;
    }

    (db_cursor!=NULL)?(db_cursor->c_close(db_cursor)):(1);
    (dbp!=NULL)?(close_db_conexion(&dbp, db_path)):(1);
    axl_env->close(axl_env,0);

    wblprintf(LOG_INFO,"LEARN_AXL","Total %d records\n",i);
}

void axl_dump(char *db_path,char *file_path){

    DB *dbp=NULL;
    DB_ENV *axl_env;
    //u_int32_t db_flags;
    DBC *db_cursor;
    DBT key,data;
    FILE *file;

    if(create_env(&axl_env,AXL_LEARN_ENV_PATH)!=DB_OK){
        wblprintf(LOG_CRITICAL,"LEARN_AXL","Could not create environment\n");
        exit(EXIT_FAILURE);
    }
    /* If the database can't be open.*/
    if(create_db_conexion(&dbp, axl_env, db_path, DB_CREATE)!=DB_OK){
        wblprintf(LOG_CRITICAL,"LEARN_AXL","Could not open database\n");
        exit(EXIT_FAILURE);
    }
    /*
    if(db_create(&dbp,NULL,0)!=0){
        wblprintf(LOG_CRITICAL,"LEARN_AXL","Could not create database\n");
        exit(1);
    }

    db_flags= DB_CREATE;

    if (dbp->open(dbp,NULL, db_path, NULL, DB_HASH, db_flags,0) !=0 ){
        wblprintf(LOG_CRITICAL,"LEARN_AXL","Could not open database\n");
        exit(1);
    }
    */
    dbp->cursor(dbp,NULL,&db_cursor,0);

    memset(&key,0,sizeof(DBT));
    memset(&data,0,sizeof(DBT));

    file = fopen(file_path,"wb");

    if(file==NULL){
        wblprintf(LOG_CRITICAL,"LEARN_AXL","File not open\n");
        exit(1);
    }
    int i=0;
    /* For each token is stored its number of spam and ham messages and its probability.*/
    while (db_cursor->get(db_cursor,&key,&data,DB_NEXT)==0){
        printf("  KEY %s\n",(char *)key.data);
        printf("  SPAM: %ld\n",((axl_info *)data.data)->spam);
        printf("  HAM: %ld\n",((axl_info *)data.data)->ham);
        fwrite(((char *)key.data),sizeof(char)*(strlen(key.data)+1),1,file);
        fwrite(((axl_info *)data.data),sizeof(axl_info),1,file);
        i++;
    }

    if(fclose(file)!=0)
        wblprintf(LOG_CRITICAL,"LEARN_AXL","Could not close file\n");    

    if(db_cursor!=NULL) db_cursor->c_close(db_cursor);

    if(dbp!=NULL) close_db_conexion(&dbp, db_path);
    axl_env->close(axl_env,0);

    wblprintf(LOG_INFO,"LEARN_AXL","Total %d records saved\n\t\t\t\t\t       Export succesfully completed\n",i);

}