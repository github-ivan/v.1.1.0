/* 
 * File:   main_parser.c
 * Author: drordas
 *
 * Created on 13 de junio de 2012, 17:10
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "eml_parser.h"
#include "list_files.h"
#include "fileutils.h"
#include "header_parser.h"
#include "html.h"
//#include "rxl_plugin.h"
//#include "spf_plugin.h"
/*
 * 
 */
int main(int argc, char** argv) {
    if(argc<2){
        printf("Invalid number of parameters\n");
        return EXIT_FAILURE;
    }
    
    //filelist *site_config_path_fl=list_files(argv[1],"eml");
    //int i=0;
    //int count_files=0;
    
    //rxl_data *rxld=create_rxl();
    //spf_data *spfd=create_spf();
    //spf_data *spfd=NULL;
    
    //if ( (count_files=count_files_filelist(site_config_path_fl)) ==0){
    //    printf("Unable to find files\n");
    //    free_filelist(site_config_path_fl);
    //    exit(EXIT_FAILURE);
    //}
    
    printf("===========================BEGIN===========================\n");
    
    char *result=NULL;
    char *dumped=NULL;
    //for(i=0;i<count_files;i++){
        //if(ae_load_eml_to_memory(get_file_at(site_config_path_fl,i),&result)>=0)
    if(ae_load_eml_to_memory(argv[1],&result)>=0){
        printf("1-Parsing email: %s\n",argv[1]);
        rfc2822eml parsed_mail=parser_mail(result);
        dumped=dump_text(parsed_mail);
        printf("2-Dumped email content\n",dumped);
        //printf("...Text dumped %s\n\n",dumped);
        //printf("Freeying dumped text\n");
        //(dumped!=NULL)?(free(dumped)):(0);
/*
        printf("1\n");
        printf("RXL-DNSWL: %d\n",rxl_check(rxld,parsed_mail,"\"list.dnswl.org\""));

        printf("2\n");
        printf("RXL-ZEN.SPAMHAUS:%d\n",rxl_check(rxld,parsed_mail,"\"zen.spamhaus.org\""));
        printf("3\n");
*/

//            printf("SPF_PASS: %d\n",spf_pass(spfd,parsed_mail,NULL));
        //printf("4\n");
        /*
        printf("SPF_FAIL: %d\n",spf_fail(spfd,parsed_mail,NULL));
        printf("5\n");
        printf("SPF_NEUTRAL: %d\n",spf_neutral(spfd,parsed_mail,NULL));
        printf("6\n");
        printf("SPF_SOFTFAIL: %d\n",spf_softfail(spfd,parsed_mail,NULL));
        printf("7\n");
        printf("SPF_NONE: %d\n",spf_none(spfd,parsed_mail,NULL));
*/

        //void *header_cont;
        //char *params="\"list.dnswl.org\"";
        //hashmap_get(parsed_mail,RECEIVED_HEADER,&header_cont);
        //int solution=rxl_check(parsed_mail,params,NULL);
        //if(solution==0)
        //    printf("RWL not pass list.dnswl.org\n");
        //else printf("RWL pass list.dnswl.org\n");

        //printf("2\n");
/*
        char *dumped=dump_text(parsed_mail);
        if(dumped==NULL){
            printf("=========================================================\n");
            printf("      Cannot dump eml      \n");
            printf("=========================================================\n");
        }
        else{
            printf("=========================================================\n");
            printf("%s\n",dump_text(parsed_mail));
            printf("=========================================================\n");
        }
*/
        freeEMLParser();
        free_mail(parsed_mail);
        //printfValues();
    }
    else printf("Unable to load email to memory\n");
    //}
    (result!=NULL)?(free(result)):(0);
    printf("3-Freeying data\n");
    printf("===========================END===========================\n");
    
    return (EXIT_SUCCESS);
}

