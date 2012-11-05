/***************************************************************************
*
*   File    : wblearn.c
*   Purpose : Implements the learning for bayes plugin.
*
*
*   Author  : David Ruano Ordás
*
*
*   Date    : November  03, 2011
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
#include <getopt.h>
#include "learn_spam_bayes.h"
#include "learn_spamhunting.h"
#include "learn_cms_bayes.h"
#include "learn_axl.h"
#include "logger.h"

/*---------------------------------------------------------------------------
                                                                    FUNCTIONS
 ---------------------------------------------------------------------------*/


/**
 * Display the available options for bayes learning.
 */
void print_bayes_help(char *mode){
    printf("Usage: %s --bayes [-s] [options]\n",mode);
    printf("Options:\n");
    printf("  --ham \t-a\t<ham_directory>  \t\t\tSpecify ham directory mails.\n");
    printf("  --spam \t-s\t<spam_directory> \t\t\tSpecify spam directory mails.\n");
    printf("  --export \t-e\t<database> [-f <file_path>] \t\tSpecify the database to dump\n");
    printf("\t\t\t\t\t\t\t\tOptional can specify the file location for the dumped database\n");
    printf("  --import \t-i\t<file_path> [-d <database>] \t\tSpecify the file which the database is dumped.\n");
    printf("\t\t\t\t\t\t\t\tOptional can specify a database load location\n");
    printf("  --clear \t-c\t<database> \t\t\t\tSpecify the database to delete.\n");
    printf("\t\t\t\t\t\t\t\tOptional can specify a database load location\n");
    printf("  --show \t-p\t<database> \t\t\t\tSpecify the database to show records.\n");
    printf("  --help \t-h\t\t\t\t\t\tPrint help information.\n");
}

void print_sh_help(char *mode){
    printf("Usage: %s --spamhunting [-u] [options]\n",mode);
    printf("Options:\n");
    printf("  --ham \t-a\t<ham_directory> [-d <database_path>] \tSpecify ham directory mails.\n");
    printf("  --spam \t-s\t<spam_directory> [-d <database_path>] \tSpecify spam directory mails.\n");
    printf("  --export \t-e\t\t \t\tSpecify the database to dump\n");
    printf("\t\t\t\t\t\t\t\tOptional can specify the file location for the dumped database\n");
    printf("  --import \t-i\t<database> [-d <database_path>]\t\tSpecify the file which the database is dumped.\n");
    printf("\t\t\t\t\t\t\t\tOptional can specify a database load location\n");
    printf("  --clear \t-c\t<database> \t\t\tSpecify the database to delete.\n");
    printf("\t\t\t\t\t\t\t\tOptional can specify a database load location\n");
    printf("  --help \t-h\t\t\t\t\t\tPrint help information.\n");
}

void print_axl_help(){
    printf("Usage: wb4spam --axl [options]\n");
    printf("Options:\n");
    printf("  --load \t-l\t<file_path> [-d database]  \t\tSpecify the directory to load axl entries.\n");
    printf("  --export \t-e\t<database> [-f <file_path>] \t\tSpecify the database to dump\n");
    printf("\t\t\t\t\t\t\t\tOptional can specify the file location for the dumped database\n");
    printf("  --import \t-i\t<file_path> [-d <database>] \t\tSpecify the file which the database is dumped.\n");
    printf("\t\t\t\t\t\t\t\tOptional can specify a database load location\n");
    printf("  --clear \t-c\t<database> \t\t\t\tSpecify the database to delete.\n");
    printf("\t\t\t\t\t\t\t\tOptional can specify a database load location\n");
    printf("  --show \t-p\t<database> \t\t\t\tSpecify the database to show records.\n");
    printf("  --help \t-h\t\t\t\t\t\tPrint help information.\n");
}

void printhelp(char *mode){
    printf("Wirebrush learning application\n");
    printf("Use modes:\n");
    print_bayes_help(mode);
    print_sh_help(mode);
    (strstr(mode,"wb4spam")!=NULL)?(print_axl_help()):(0);
}

/**
 * Indicates if there was an error introducing arguments.
 */
void error(char *mode){
    printf("Error. Incorrect arguments\n");
    printf("       Introduce %s -h for more information\n",mode);
    abort();
}

#define SPAM_BAYES_DEFAULT_DB "wb4spam_bayes.db"
#define SPAM_BAYES_DUMPED_DB "wb4spam_bayes.dump"
#define SPAM_PAIRS_DEFAULT_DB "wb4spam_pairs.db"
#define SPAM_EMAIL_DEFAULT_DB "wb4spam_email.db"
#define SPAM_TOKENS_DEFAULT_DB "wb4spam_tokens.db"


#define CMS_BAYES_DEFAULT_DB "wb4cms_bayes.db"
#define CMS_BAYES_DUMPED_DB "wb4cms_bayes.dump"
#define CMS_PAIRS_DEFAULT_DB "wb4cms_pairs.db"
#define CMS_EMAIL_DEFAULT_DB "wb4cms_email.db"
#define CMS_TOKENS_DEFAULT_DB "wb4Cms_t"

#define BAYES 0
#define SPAMHUNTING 1
#define AXL 2
#define NONE -1

#define DUMP 2
#define IMPORT 3
#define CLEAR 4
#define PRINT 5
#define SAVE 6
#define HELP 7
#define LOAD 8

#define CMS_LEARN 1
#define SPAM_LEARN 0


/**
 * Main function for bayes learning.
 */
int main(int argc, char* argv[]) {

    int op;
    char *ham_dir=NULL, *spam_dir=NULL,*db_path=NULL, *temp=NULL, program_type=SPAM_LEARN;
    char *dump_path=NULL, *import_path=NULL,*out_path=NULL, *clear_path=NULL, *load_path=NULL;
    
    short ham=0, spam=0, db=0, method=NONE, output=0, print=0, type=NONE;

    static struct option op_largas[] =
    {
        { "bayes",              no_argument,        0,  'b' },
        { "spamhunting",        no_argument,        0,  'u' },
        { "axl",                no_argument,        0,  'x' },        
        { "ham",                required_argument,  0,  'a' },
        { "spam",               required_argument,  0,  's' },
        { "load",               required_argument,  0,  'l' },
        { "export",             required_argument,  0,  'e' },
        { "import",             required_argument,  0,  'i' },
        { "clear" ,             required_argument,  0,  'c' },
        { "file",               required_argument,  0,  'f' },
        { "database",           required_argument,  0,  'd' },
        { "show",               required_argument,  0,  'p' },
        { "help",               no_argument,        0,  'h' },
        { 0,                    0,                  0,  0   }
    };

    if(argc<2){ 
        printhelp(argv[0]);
        return 1;
    }

    while((op = getopt_long(argc, argv,"bua:s:e:l:i:c:f:d:p:h",op_largas,NULL))!=-1){
        switch(op){
            case 'b':type=BAYES;
                     break;
            case 'u':type=SPAMHUNTING;
                     break;
            case 'x':type=AXL;
                     break;                     
            case 'a':method=SAVE;
                     ham=1;
                     ham_dir=optarg;
                     break;
            case 's':method=SAVE;
                     spam=1;
                     spam_dir=optarg;
                     break;
            case 'e':method=DUMP;
                     dump_path=optarg;
                     break;
            case 'c':method=CLEAR;
                     clear_path=optarg;
                     break;
            case 'i':method=IMPORT;
                     import_path=optarg;
                     break;
            case 'l':method=LOAD;
                     load_path=optarg;
                     break;                     
            case 'f':output=1;
                     out_path=optarg;
                     break;
            case 'd':db=1;
                     db_path=optarg;
                     break;
            case 'p':method=PRINT;
                     print=1;
                     db_path=optarg;
                     break;   
            case 'h':method=HELP;
                     break;
            default :error(argv[0]);
                     break;
        }
    }

    
    (strstr(argv[0],"wb4cms")!=NULL)?
        (program_type=CMS_LEARN):
        (program_type=SPAM_LEARN);
    
    
    if(program_type==SPAM_LEARN){
        if(type==NONE){
            if (method==HELP) printhelp(argv[0]);
            else{
                error(argv[0]);
                exit(EXIT_FAILURE);
            }
        }
        if(type==BAYES){
            wblprintf(LOG_INFO,"wb4spaml","Executing Bayesian learning platform\n");
            switch(method){
                case NONE: error(argv[0]);
                           exit(EXIT_FAILURE);
                           break;
                case DUMP: (output)?(db_dump(dump_path,out_path)):(db_dump(dump_path,SPAM_BAYES_DUMPED_DB));
                           break;
                case IMPORT: (db)?db_load(import_path,db_path):(db_load(import_path,SPAM_BAYES_DEFAULT_DB));
                           break;
                case CLEAR: if( (temp=(char *)malloc(sizeof(char)*strlen(clear_path)+8))==NULL){
                                wblprintf(LOG_INFO,"wb4spaml","Error: Not enough space\n");
                                exit(EXIT_FAILURE);
                            }
                            sprintf(temp,"rm -fr %s",clear_path);
                            (system(temp)!=-1)?
                                (wblprintf(LOG_INFO,"wb4spaml","Database %s, succesfully deleted\n",clear_path)):
                                (wblprintf(LOG_INFO,"wb4spaml","Error: Unable to delete %s database\n",clear_path));
                                free(temp);
                            break;
                case PRINT: db_print(db_path);
                            break;
                case SAVE: (spam)?
                           (load_directory_mail(spam_dir,SPAM_BAYES_DEFAULT_DB,OPT_SPAM)):
                           (load_directory_mail(ham_dir,SPAM_BAYES_DEFAULT_DB,OPT_HAM));
                           break;
                case LOAD: wblprintf(LOG_WARNING,"wb4spaml","Invalid option for Bayesian learning platform\n");
                           print_bayes_help(argv[0]);
                           break;
                default:   print_bayes_help(argv[0]);
                           break;                           
            }
        }else if(type==SPAMHUNTING){
            wblprintf(LOG_INFO,"wb4spaml","Executing SpamHunting SPAM learning platform\n");  
            switch(method){
                case NONE: error(argv[0]);
                           exit(EXIT_FAILURE);
                           break;
                case DUMP: (output)?(set_dump_path_sh(out_path)):(0);
                           db_dump_tokens(SPAM_TOKENS_DEFAULT_DB);
                           db_dump_email(SPAM_EMAIL_DEFAULT_DB);
                           db_dump_pairs(SPAM_PAIRS_DEFAULT_DB);
                           break;
                case IMPORT: db_load_tokens();
                           db_load_email();
                           db_load_pairs();
                           break;
                case CLEAR: if( (temp=(char *)malloc(sizeof(char)*strlen(clear_path)+8))==NULL){
                                wblprintf(LOG_INFO,"wb4spaml","Error: Not enough space\n");
                                exit(EXIT_FAILURE);
                            }
                            sprintf(temp,"rm -fr %s",clear_path);
                            (system(temp)!=-1)?
                                (wblprintf(LOG_INFO,"wb4spaml","Database %s, succesfully deleted\n",clear_path)):
                                (wblprintf(LOG_INFO,"wb4spaml","Error: Unable to delete %s database\n",clear_path));
                                free(temp);
                            break;
                case PRINT: db_print(db_path);
                            break;
                case SAVE: (spam)?
                           (load_directory_mail_sh(spam_dir,OPT_SPAM)):
                           (load_directory_mail_sh(ham_dir,OPT_HAM));
                           break;
                case LOAD: wblprintf(LOG_WARNING,"wb4spaml","Invalid option for SpamHunting SPAM learning platform\n");
                           print_sh_help(argv[0]);
                           break;
                default:   print_sh_help(argv[0]);
                           break;                           
            }
        }else{
            wblprintf(LOG_INFO,"wb4spaml","Executing Auto White/Black List SPAM learning platform\n");  
            switch(method){
                case NONE: error(argv[0]);
                           exit(EXIT_FAILURE);
                           break;
                case LOAD: if(db) load_axl_file(load_path,db_path);
                           else load_axl_file(load_path,default_axl_db);
                           break;
                case IMPORT: wblprintf(LOG_INFO,"wb4spam","NOT YET\n");
                             break;
                case DUMP: if(output) axl_dump(dump_path,out_path);
                           else axl_dump(dump_path,default_axl_dump_file);                             
                           break;
                case CLEAR: if( (temp=(char *)malloc(sizeof(char)*strlen(clear_path)+8))==NULL){
                                wblprintf(LOG_INFO,"wb4spaml","Error: Not enough space\n");
                                exit(EXIT_FAILURE);
                            }
                            sprintf(temp,"rm -fr %s",clear_path);
                            (system(temp)!=-1)?
                                (wblprintf(LOG_INFO,"wb4spaml","Database %s, succesfully deleted\n",clear_path)):
                                (wblprintf(LOG_INFO,"wb4spaml","Error: Unable to delete %s database\n",clear_path));
                                free(temp);
                            break;
                case PRINT: (db)?(axl_print(db_path)):(axl_print(default_axl_db));
                            break;
                case HELP: print_axl_help();
                           break;
                default:   wblprintf(LOG_WARNING,"wb4spaml","Invalid option for AXL SPAM learning platform\n");
                           print_axl_help();
                           break;                           
            }
        }
    }else{
        wblprintf(LOG_INFO,"wb4cmsl","Executing CMS filtering platform\n");
        if(type==NONE){
            if (method==HELP) printhelp(argv[0]);
            else{
                error(argv[0]);
                exit(EXIT_FAILURE);
            }
        }
        if(type==BAYES){
            wblprintf(LOG_INFO,"wb4cmsl","Executing Bayesian CMS learning platform\n");
            switch(method){
                case NONE: error(argv[0]);
                           exit(EXIT_FAILURE);
                           break;
                case DUMP: (output)?(db_dump(dump_path,out_path)):(db_dump(dump_path,SPAM_BAYES_DUMPED_DB));
                           break;
                case IMPORT: (db)?db_load(import_path,db_path):(db_load(import_path,CMS_BAYES_DEFAULT_DB));
                           break;
                case CLEAR: if( (temp=(char *)malloc(sizeof(char)*strlen(clear_path)+8))==NULL){
                                wblprintf(LOG_INFO,"wb4cmsl","Error: Not enough space\n");
                                exit(EXIT_FAILURE);
                            }
                            sprintf(temp,"rm -fr %s",clear_path);
                            (system(temp)!=-1)?
                                (wblprintf(LOG_INFO,"wb4cmsl","Database %s, succesfully deleted\n",clear_path)):
                                (wblprintf(LOG_INFO,"wb4cmsl","Error: Unable to delete %s database\n",clear_path));
                            free(temp);
                            break;
                case PRINT: db_print(db_path);
                            break;
                case SAVE: (spam)?
                           (cms_load_directory_mail(spam_dir,CMS_BAYES_DEFAULT_DB,OPT_SPAM)):
                           (cms_load_directory_mail(ham_dir,CMS_BAYES_DEFAULT_DB,OPT_HAM));
                           break;
                case LOAD: wblprintf(LOG_WARNING,"wb4cmsl","Invalid option for Bayesian CMS learning platform\n");
                           print_bayes_help(argv[0]);
                           break;
                default:   print_bayes_help(argv[0]);
                           break;
            }
        }
        else if(type==SPAMHUNTING){
            wblprintf(LOG_INFO,"wb4cmsl","Executing SpamHunting CMS learning platform\n");
            switch(method){
                case NONE: error(argv[0]);
                           exit(EXIT_FAILURE);
                           break;
                case DUMP: (output)?(set_dump_path_sh(out_path)):(0);
                           db_dump_tokens(CMS_TOKENS_DEFAULT_DB);
                           db_dump_email(CMS_EMAIL_DEFAULT_DB);
                           db_dump_pairs(CMS_PAIRS_DEFAULT_DB);
                           break;
                case IMPORT:db_load_tokens();
                           db_load_email();
                           db_load_pairs();
                           break;
                case CLEAR: if( (temp=(char *)malloc(sizeof(char)*strlen(clear_path)+8))==NULL){
                                wblprintf(LOG_INFO,"wb4cmsl","Error: Not enough space\n");
                                exit(EXIT_FAILURE);
                            }
                            sprintf(temp,"rm -fr %s",clear_path);
                            (system(temp)!=-1)?
                                (wblprintf(LOG_INFO,"wb4cmsl","Database %s, succesfully deleted\n",clear_path)):
                                (wblprintf(LOG_INFO,"wb4cmsl","Error: Unable to delete %s database\n",clear_path));
                                free(temp);
                            break;
                case PRINT: db_print(db_path);
                            break;
                case SAVE: printf("PENDDING...\n");
                           //(spam)?
                           //(cms_load_directory_mail_sh(spam_dir,OPT_SPAM)):
                           //(cms_load_directory_mail_sh(ham_dir,OPT_HAM));
                           break;
                case LOAD: wblprintf(LOG_WARNING,"wb4cmsl","Invalid option for SpamHunting CMS learning platform\n");
                           print_sh_help(argv[0]);
                           break;                            
                default:   print_sh_help(argv[0]);
                           break;                          
            }
        }else wblprintf(LOG_INFO,"wb4cmsl","AXL option invalid for CMS filtering platform\n");
    }

    return (EXIT_SUCCESS);
}
