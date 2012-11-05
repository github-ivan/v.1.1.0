/***************************************************************************                        
*
*   File    : csa.c
*   Purpose : Implements main program for Wirebrush. It loads the plugin
*      structure, the target email and uses the core functionality in order
*      to filter a message
*            
*   Author: David Ruano, Noemi Perez, Jose Ramon Mendez
* 
* 
*   Date    : October  14, 2010
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

#include <stdio.h>
#include <stdlib.h>
#include <cpluff.h>
#include <locale.h>
#include <unistd.h>
#include <string.h>
#include "fileutils.h"
#include "iniparser.h"
#include <getopt.h>

#define CMS_PLUGIN_LIST "wb4cms_plugins.list"
#define SPAM_PLUGIN_LIST "wb4spam_plugins.list"

#define PLUGIN_LIST_FILE "plugins.list"
#define EMAIL_CONTENT datainterchangearea[0]
#define EMAIL_REPORT datainterchangearea[1]
#define EMAIL_SCORES datainterchangearea[2]
#define LEARN_METHOD datainterchangearea[3]
#define PROGRAM_TYPE datainterchangearea[4]

#define AUTO_LEARN 'a'
#define LEARN_SPAM 's'
#define LEARN_HAM 'h'
#define NO_LEARN 'n'

#define CMS_FILTER 1
#define SPAM_FILTER 0

void handle_fatal_error(const char *msg);
void initialize();
cp_context_t *new_context();
void load_plugins(cp_context_t *ctx, char *plugin_list);
void start_plugin(char *args[], cp_context_t *ctx, const char *plugin);
void printhelp();

char **datainterchangearea;

cp_context_t *ctx;

int main(int argc, char* argv[]){
        
    int op;
    char *email=NULL;
    char l_method='a';
    char *program_type=strstr(argv[0],"wb4");
    char *plugin_path=SPAM_PLUGIN_LIST;
   

    static struct option op_largas[] =
    {
        { "learn-spam", required_argument,  0,  's' },
        { "learn-ham",  required_argument,  0,  'a' },
        { "no-learn",   required_argument,  0,  'n' },
        { "help",       no_argument,        0,  'h' },        
        { 0,            0,                  0,  0   }
    };
    
    if(argc<=1){
        printhelp();
        return 1;
    }
    else{ 
        if(argc==2){
            email=argv[1];
            l_method=AUTO_LEARN;
        }
        else{
            while((op = getopt_long(argc, argv,"s:a:n:h",op_largas,NULL))!=-1){
                switch(op){
                    case 's': l_method=LEARN_SPAM;
                              email=optarg;
                              break;
                    case 'a': l_method=LEARN_HAM;
                              email=optarg;
                              break;
                    case 'n': l_method=NO_LEARN;
                              email=optarg;
                              break;
                    case 'h': printhelp();
                              break;                          
                    default : l_method=AUTO_LEARN;
                              email=optarg;
                              printf("Invalid option. Assuming auto-learning\n");
                              break;
                }
            }
        }
    }

    initialize();
    ctx=new_context();
    
    datainterchangearea=malloc(5*sizeof(char *));
    LEARN_METHOD=malloc(sizeof(char)*2);
    sprintf(LEARN_METHOD,"%c",l_method);
    EMAIL_CONTENT=malloc(sizeof(char));
    strcpy(EMAIL_CONTENT,"");
    PROGRAM_TYPE=malloc(2*sizeof(char));
    if(strstr(program_type,"wb4cms")!=NULL){
        sprintf(PROGRAM_TYPE,"%d",CMS_FILTER);
        plugin_path=CMS_PLUGIN_LIST;
    }
    else{
        sprintf(PROGRAM_TYPE,"%d",SPAM_FILTER);
        plugin_path=SPAM_PLUGIN_LIST;
    }
    
    load_plugins(ctx,plugin_path);
    
    EMAIL_REPORT=NULL;
    EMAIL_SCORES=NULL;
    
    start_plugin(datainterchangearea,ctx,"es.uvigo.ei.core");

    free(EMAIL_CONTENT);
    EMAIL_CONTENT=NULL;

    //printf("Loading file %s...\n",argv[1]);
    if(ae_load_eml_to_memory(email,&EMAIL_CONTENT)>=0){
        printf("Classifiying file %s....\n",email);

        cp_run_plugins_step(ctx);

        printf("Done.\nResult: %s %s\n",EMAIL_SCORES, EMAIL_REPORT);

        if (EMAIL_CONTENT!=NULL){
            free(EMAIL_CONTENT);
            EMAIL_CONTENT=NULL;
        }
        if (EMAIL_REPORT!=NULL){ 
            free(EMAIL_REPORT);
            EMAIL_REPORT=NULL;
        }
        if (EMAIL_SCORES!=NULL){ 
            free(EMAIL_SCORES);
            EMAIL_SCORES=NULL;
        }
        if(LEARN_METHOD!=NULL){ 
            free(LEARN_METHOD);
            LEARN_METHOD=NULL;
        }
        if(PROGRAM_TYPE!=NULL){ 
            printf("entro aqui\n");
            free(PROGRAM_TYPE);
            PROGRAM_TYPE=NULL;
        }
    }

    free(datainterchangearea);
    //printf("done\n");
    cp_stop_plugins(ctx);
    
    cp_uninstall_plugins(ctx);   

    cp_destroy_context(ctx);

    cp_destroy();

    return EXIT_SUCCESS;      
}

void initialize(){
    cp_status_t status;
    cp_set_fatal_error_handler(handle_fatal_error);
    status=cp_init();
    if (status != CP_OK){
       printf("Inicialization error. Exiting...\n");
       exit(EXIT_FAILURE);
    }
}

cp_context_t *new_context(){
    cp_status_t status;
    cp_context_t *retval;

    retval=cp_create_context(&status);

    if (retval==NULL){
       printf("Unable to create context. Exiting...\n");
       exit(EXIT_FAILURE);
    }
    return retval;
}

void load_plugins(cp_context_t *ctx, char *plugin_list){
    FILE *lf;
    char plugindir[256];
    char cwd[768];
    char realpluginpath[1024];
    if(getcwd(cwd, sizeof(cwd)) == NULL) strcpy(cwd,"");

    lf = fopen(plugin_list,"r");
    if (lf==NULL){
       printf("Unable to load plugin list file (%s). Exiting...\n",plugin_list);
       exit(EXIT_FAILURE);
    }
    while (fgets(plugindir,256,lf) != NULL) {
       cp_plugin_info_t *plugininfo;
       cp_status_t status;
       int i;
 
       //Remove possible trailing newline from plugin location 
       for (i=0; plugindir[i+1] != '\0'; i++);
       if (plugindir[i] == '\n') plugindir[i]='\0';
       strcpy(realpluginpath,cwd);
       strcat(realpluginpath,"/");
       strcat(realpluginpath,plugindir);

       //Load plugin descriptor
       if ( (plugininfo = cp_load_plugin_descriptor(ctx, realpluginpath, &status) ) == NULL) {
           printf("Unable to load plugin descriptor: %s. Exiting...\n", realpluginpath);
           exit(EXIT_FAILURE    );
       }
       
       //printf("plugin info:\n  name: %s\n  path: %s\n",plugininfo->name,plugininfo->plugin_path);
       //printf("                num extensions: %d\n",plugininfo->num_extensions);
       
       //Install plugin descriptor
       status=cp_install_plugin(ctx, plugininfo);
       if(status != CP_OK) {
          printf("Unable to install plugin: %s. Exiting...\n", plugindir);
          exit(EXIT_FAILURE);
       }
    
       //Release plugin descriptor information 
       cp_release_info(ctx,plugininfo);
    }

    //Close plugin list file
    fclose(lf);
}

void start_plugin(char *args[], cp_context_t *ctx, const char *plugin){
    
    //Set plugin startup arguments
    cp_set_context_args(ctx, args);

    //Start the core plugin, possibly activating other plugins as well
    if (cp_start_plugin(ctx, plugin) != CP_OK){
       printf("Unable to start plugin %s.\n", plugin);
    }
    
}

void handle_fatal_error(const char *msg){
    wblprintf(LOG_CRITICAL,"","Error: %s\n",msg);
    exit(EXIT_FAILURE);
}
 
void printhelp(){
    printf("Usage: w4spam [options] <email>\n");
    printf("Options:\n");
    printf("  --learn-spam \t-s\t <email>  \t\t\tInvoques wb4spam and learns email as spam\n");
    printf("  --learn-ham \t-h\t <email>  \t\t\tInvoques wb4spam and learns email as ham\n");
    printf("  --no-learn \t-n\t<email> \t\tInvoques wb4spam with no learning option\n");
    printf("  --help \t-h\t\t\t\t\t\tPrint help information.\n");
}

void error(){
    printf("Error. Incorrect arguments\n");
    printf("       Introduce w4spam -help for more information\n");
    abort();
}