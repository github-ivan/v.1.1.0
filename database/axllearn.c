/***************************************************************************
*
*   File    : axllearn.c
*   Purpose : Implements the learning for bayes plugin.
*
*
*   Author  : David Ruano Ordás
*
*
*   Date    : September  03, 2011
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
#include "learn_axl.h"

#define default_axl_db "axl.db"
#define default_axl_dump_file "dump_axl.dat"

/*---------------------------------------------------------------------------
                                                                    FUNCTIONS
 ---------------------------------------------------------------------------*/


/**
 * Display the available options for bayes learning.
 */
void printhelp(){
    printf("Usage: axllearn [options]\n");
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

/**
 * Indicates if there was an error introducing arguments.
 */
void error(){
    printf("Error. Incorrect arguments\n");
    printf("       Introduce axllearn -h for more information\n");
    abort();
}

/**
 * Main function for bayes learning.
 */
int main(int argc, char* argv[]) {

    int op;
    char *file_dir=NULL,*db_path=NULL;
    char *dump_path=NULL, *load_path=NULL,*out_path=NULL, *clear_path=NULL;
    
    short load=0, db=0, dump=0, output=0, clear=0, print=0, file=0;

    static struct option op_largas[] =
    {
        { "load",       required_argument,  0,  'l' },
        { "export",     required_argument,  0,  'e' },
        { "import",     required_argument,  0,  'i' },
        { "clear" ,     required_argument,  0,  'c' },
        { "file",       required_argument,  0,  'f' },
        { "database",   required_argument,  0,  'd' },
        { "show",       required_argument,  0,  'p' },
        { "help",       no_argument,        0,  'h' },
        { 0,            0,                  0,  0   }
    };

    if(argc<2){ 
        printhelp();
        return 1;
    }

    while((op = getopt_long(argc, argv,"l:e:i:c:f:d:p:h",op_largas,NULL))!=-1)
        switch(op){

            case 'l':file=1;
                     file_dir=optarg;
                     break;
            case 'e':dump=1;
                     dump_path=optarg;
                     break;
            case 'c':clear=1;
                     clear_path=optarg;
                     break;
            case 'i':load=1;
                     load_path=optarg;
                     break;
            case 'f':output=1;
                     out_path=optarg;
                     break;
            case 'd':db=1;
                     db_path=optarg;
                     break;
            case 'p':print=1;
                     db_path=optarg;
                     break;   
            case 'h':printhelp();
                     break;
            default :error();
                     break;
        }

        if(file){
            if(db) load_axl_file(file_dir,db_path);
            else load_axl_file(file_dir,default_axl_db);
        }
        if(print){
            if(db) axl_print(db_path);
            else axl_print(default_axl_db);
        }
        if(dump){
            if(output) axl_dump(dump_path,out_path);
            else axl_dump(dump_path,default_axl_dump_file);
        }
        if(clear){
            char *temp=(char *)malloc(sizeof(char)*strlen(clear_path)+8);
            if(temp==NULL){
                printf("Error: Not enough space\n");
                exit(EXIT_FAILURE);
            }
            sprintf(temp,"rm -fr %s",clear_path);

            if(system(temp)!=-1)
                printf("Database %s, succesfully deleted\n",clear_path);
            else
                printf("Error: Unable to delete %s database\n",clear_path);
            free(temp);
        }
        if(load){
            //if(db) awl_load(load_path,db_path);
            //else awl_load(load_path,default_awl_db);
            printf("FALTA DEFINIR LA FUNCION QUE CARGUE DE %s\n",load_path);
        }
        
        
    return (EXIT_SUCCESS);
}

