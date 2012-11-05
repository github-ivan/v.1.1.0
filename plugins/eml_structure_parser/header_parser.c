/***************************************************************************
*
*   File    : header_parser.h
*   Purpose : Implements a parser for received headers.
*
*   Author: David Ruano
*
*
*   Date    : March  10, 2010
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


#include "header_parser.h"
#include "hashmap.h"
#include <stdio.h>
#include <stdlib.h>
#include "logger.h"
#include "linked_list.h"
#include "eml_parser.h"
#include <ctype.h>

struct received_header{
    char *received_domain;
    char *received_ip;
    char *from_domain;
};


ip_info *get_header_info(rfc2822eml email, int position){

    linklist *list_received;
    char *received, *from;
    char *start_pointer;
    char *at;
    int last=0, count =0, first =0;
    ip_info *info=(ip_info *)malloc(sizeof(ip_info));

   
    //printf("   __FULL FROM: %s\n",(char *)from);
    

    info->from_domain=NULL;
    info->received_domain=NULL;
    info->received_ip=NULL;


    //printf("   __FULL RECEIVED: %s\n",start_pointer);
    
    //PARSING RECEIVED
   
    if(hashmap_get(email,RECEIVED_HEADER,(any_t *)&list_received)==MAP_MISSING){
        wblprintf(LOG_WARNING,"HEADER PARSER","Received headers does not exist\n");
    }
    else{
        if(getlengthlist(list_received)==0){
                wblprintf(LOG_WARNING,"HEADER PARSER","Received headers does not exist\n");
        }
        else
            if( position<0 || position>getlengthlist(list_received) ){
                wblprintf(LOG_WARNING,"HEADER PARSER","Position not valid. Assuming first header\n");
                position=1;
            }

        if(getatlist(list_received,(position-1),(element *)&received)!=NODE_OK){
            wblprintf(LOG_WARNING,"HEADER PARSER","%dº received does not exist\n",position);
        }
        else{

            if(received==NULL || strlen(received)<=0 ){
                wblprintf(LOG_WARNING,"HEADER PARSER","Header content not found\n");
            }
            else{
                //printf("   __BEGIN [GETTING RECEIVED DOMAIN]\n");
                start_pointer=received;
                
                if( (at=strstr(start_pointer,"from"))==NULL ){
                    wblprintf(LOG_WARNING,"HEADER_PARSER","Unable to parse domain\n");
                }
                else{
                    char *by=strstr(start_pointer,"by");
                    if(by!=NULL && (by-start_pointer < at-start_pointer) ){
                        wblprintf(LOG_WARNING,"HEADER_PARSER","from domain not found\n");
                    }
                    else{
                        count=at-start_pointer+4;
                        //printf("     __RECEIVED DOMAIN[%d]: %c\n",count,start_pointer[count]);
                        while(!isalpha(start_pointer[count]) && start_pointer[count]!='\0') 
                            count++;

                        if(start_pointer[count]!='\0'){
                            first=count;
                            while( isalnum(start_pointer[count]) || start_pointer[count]=='.' )
                                count++;

                            last=count;

                            if(first<last){
                                start_pointer=&start_pointer[first];
                                info->received_domain=malloc(sizeof(char)*(last-first+2));
                                memcpy(info->received_domain,start_pointer,(last-first+1)*sizeof(char));
                                info->received_domain[last-first+1]='\0';
                                if(strchr(info->received_domain,'.')==NULL){
                                   wblprintf(LOG_WARNING,"HEADER_PARSER","Malformed domain name\n");
                                   printf("     __MALFORMED RECEIVED DOMAIN: %s\n",info->received_domain);
                                   free(info->received_domain);
                                   info->received_domain=NULL;
                                }
                                count=last-first;
                                //printf("     __RECEIVED DOMAIN: %s\n",info->received_domain);
                            }else{ 
                                wblprintf(LOG_WARNING,"HEADER_PARSER","Domain length incorrect\n");
                                info->received_domain=NULL;
                            }
                        }
                        else{
                            wblprintf(LOG_WARNING,"HEADER_PARSER","Domain not found\n");
                            info->received_domain=NULL;
                        }
                    }
                }

                while(start_pointer[count] !='\n'){
                    if(start_pointer[count]=='[')
                        first=count+1;
                    if(start_pointer[count]==']'){
                        last=count-1;
                        break;
                    }
                    count++;
                }

                if(last-first>=7 && last-first<=15){
                    start_pointer=&start_pointer[first];
                    info->received_ip=(char *)malloc(sizeof(char)*last-first+2);
                    memcpy(info->received_ip,start_pointer,(last-first+1)*sizeof(char));
                    info->received_ip[last-first+1]='\0';
                    //printf("     __RECEIVED IP: %s\n",info->received_ip);
                }
                else{
                    wblprintf(LOG_WARNING,"HEADER PARSER","Ip is not correct\n");
                    info->received_ip=NULL;
                }

                //printf("   __END [GETTING RECEIVED IP]\n");
            }
        }
    }
    
    //PARSING FROM DOMAIN
    
    if(hashmap_get(email,FROM_HEADER,(any_t *)&from)==MAP_MISSING){
        wblprintf(LOG_CRITICAL,"HEADER PARSER","From does not exist\n");
    }
    else{
        start_pointer=from;
        //printf("   __FULL FROM: %s\n",start_pointer);

        //printf("   __BEGIN [GETTING FROM DOMAIN]\n");

        first=count=0;
        if( ( at=(strchr(start_pointer,'@')) )==NULL ){
            wblprintf(LOG_WARNING,"HEADER PARSER","From domain is not correct\n");
            info->from_domain=NULL;
        }
        else{
            first=count=(at-start_pointer+1);
            //printf("     __FIRST %d\n",first);
            while(start_pointer[count]!='\n' && start_pointer[count]!='>'
              && start_pointer[count]!=' ' && start_pointer[count]!='\0'){
              count++;
            }    
            last=--count;

            start_pointer=&start_pointer[first];

            info->from_domain=malloc(sizeof(char)*(last-first+2));
            memcpy(info->from_domain,start_pointer,(last-first+1)*sizeof(char));
            info->from_domain[last-first+1]='\0';

            //printf("     __FROM DOMAIN %s\n",info->from_domain);
        }
    }
    
    //printf("   __END [GETTING FROM DOMAIN]\n");
    
    return info;
}

char *get_received_domain(ip_info *info){
    if(info!=NULL) 
        return info->received_domain;
    else return NULL;
}

char *get_received_ip(ip_info *info){
    if(info==NULL || info->received_ip==NULL) 
      return NULL;
    else return info->received_ip;
}

char *get_from_domain(ip_info *info){
    if(info==NULL || info->from_domain==NULL)
        return NULL;
    else return info->from_domain;
}

void free_ip(ip_info *info){

    if(info!=NULL){
        if(info->from_domain!=NULL)
            free(info->from_domain);
        if(info->received_domain!=NULL)
            free(info->received_domain);
        if(info->received_ip!=NULL)
            free(info->received_ip);
        free(info);
    }
}

char **parse_ip(char *ip){
    
    if(ip==NULL || strlen(ip)==0){
        wblprintf(LOG_WARNING,"HEADER PARSER","Unable to parse ip\n");
        return NULL;
    }
    
    char **aux=malloc(sizeof(char *)*4);
    char *octect;
    char *res=malloc(sizeof(char)*(strlen(ip)+1));
    strcpy(res,ip);

    if((octect=strtok(res,"."))==NULL){
        free(res);
        return NULL;
    }
    aux[0]=malloc(sizeof(char)*(strlen(octect)+1));
    strcpy(aux[0],octect);

    if((octect=strtok(NULL,"."))==NULL){ 
        free(aux[0]);
        free(aux);
        free(res);
        return NULL;
    }
    aux[1]=malloc(sizeof(char)*(strlen(octect)+1));
    strcpy(aux[1],octect);

    if((octect=strtok(NULL,"."))==NULL){ 
        free(aux[0]);
        free(aux[1]);
        free(aux);
        free(res);
        return NULL;
    }
    aux[2]=malloc(sizeof(char)*(strlen(octect)+1));
    strcpy(aux[2],octect);

    if((octect=strtok(NULL,"."))==NULL){ 
        free(aux[0]);
        free(aux[1]);
        free(aux[2]);
        free(aux);
        return NULL;
    }
    aux[3]=malloc(sizeof(char)*(strlen(octect)+1));
    strcpy(aux[3],octect);

    free(res);

    return aux;
}

char *get_octect(char **ip,int num){
    --num;
    if(num>=0 && num<4)
        return ip[num];
    else
        return NULL;
}

void free_parsed_ip(char **ip){
    int i=0;
    if(ip!=NULL){
        for(;i<4;i++)
            free(ip[i]);
    }
    free(ip);
}

int get_ip_size(char **ip){
    return (strlen(ip[0])+strlen(ip[1])+strlen(ip[2])+strlen(ip[3]));
}
