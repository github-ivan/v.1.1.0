/***************************************************************************
*
*   File    : shlearn.c
*   Purpose : Implements the learning for spamhunting plugin.
*
*
*   Author  : Noemí Pérez Díaz
*
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
#include <getopt.h>
#include "learn_spamhunting.h"

/*---------------------------------------------------------------------------
                                                                    FUNCTIONS
 ---------------------------------------------------------------------------*/

/**
 * Display the available options for spamhunting learning.
 */
void printhelp(){
    printf("Usage: shlearn [options]\n");
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

/**
 * Indicates if there was an error introducing arguments.
 */
void error(){
    printf("Error. Incorrect arguments\n");
    printf("       Introduce wblearn -h for more information\n");
    abort();
}

/**
 * Main function for spamhunting learning.
 */
int main(int argc, char* argv[]) {

    int op;
    char *ham_dir=NULL, *spam_dir=NULL;
    char *out_path=NULL, *clear_path=NULL;

    short ham=0, spam=0, db=0, dump=0, load=0, output=0, clear=0;

    static struct option op_largas[] =
    {
        { "ham",        required_argument,  0,  'a' },
        { "spam",       required_argument,  0,  's' },
        { "export",     no_argument,        0,  'e' },
        { "import",     no_argument,        0,  'i' },
        { "clear" ,     required_argument,  0,  'c' },
        { "file",       required_argument,  0,  'f' },
        { "help",       no_argument,        0,  'h' },
        { 0,            0,                  0,  0   }
    };

    if(argc<2){
        printhelp();
        return 1;
    }

    while((op = getopt_long(argc, argv,"a:s:eic:f:h",op_largas,NULL))!=-1)
        switch(op){

            case 'a':ham=1;
                     ham_dir=optarg;
                     break;
            case 's':spam=1;
                     spam_dir=optarg;
                     break;
            case 'e':dump=1;
                     break;
            case 'c':clear=1;
                     clear_path=optarg;
                     break;
            case 'i':load=1;
                     break;
            case 'f':output=1;
                     out_path=optarg;
                     break;
            case 'h':printhelp();
                     break;
            default :error();
                     break;
        }

    if(dump){
        if(output)
            set_dump_path_sh(out_path);
            db_dump_tokens("tokens.db");
            db_dump_email("email.db");
            db_dump_pairs("pairs.db");
    }
    else
        if(load){
            db_load_tokens();
            db_load_email();
            db_load_pairs();
        }
        else
            if(clear){

                char *temp=(char *)malloc(sizeof(char)*strlen(clear_path)+8);
                if(temp==NULL){
                    printf("Error: Not enough space\n");
                    free(temp);
                    exit(1);
                }
                sprintf(temp,"rm -fr %s",clear_path);

                if(system(temp)!=-1)
                    printf("Database %s, succesfully deleted\n",clear_path);
                else
                    printf("Error: Unable to delete %s database\n",clear_path);
                free(temp);

            }else
                if(spam || ham){
                    if(spam){
                       load_directory_mail_sh(spam_dir,OPT_SPAM);
                    }
                    else{
                       load_directory_mail_sh(ham_dir,OPT_HAM);
                    }
                }
                else if(output || db) error();


    return (EXIT_SUCCESS);
}

