/***************************************************************************
*
*   File    : eml_parser.c
*   Purpose : Implements a parser of eml messages (RFC 2822)
*
*   Author: Noemi Perez, Jose Ramon Mendez
*
*
*   Date    : October  20, 2010
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
#include <string.h>
#include "hashmap.h"
#include "linked_list.h"
#include "string_util.h"
#include "eml_parser.h"
#include "stack.h"
#include "logger.h"
#include "html.h"
#include <pthread.h>

#define STATUS_HEADERNAME 0
#define STATUS_HEADERCONTENT 1
#define STATUS_BODY 2
#define STATUS_PART_TYPE 3
#define STATUS_PART_CONTENT 4

#define BOUNDARY "boundary"
#define RAW_TEXT "raw-text"
#define PARTS "Parts"

#define MULTIPART_KEYWORD "multipart"

#define BOUNDARY_QUOT 0
#define BOUNDARY_EQUALS 1
//int countHeader=0;
//int countNormal=0;

//int uncountHeader=0;
//int uncountNormal=0;

/**
 * Definition of mime_part structure
 */
struct mime_part{
    char *header;
    char *content;
};

int free_linklist_content_string(element data);

/**
 * Return true if content type is multipart
 */
int is_multipart(char *content_type);

/**
 * Return the boundary from a content_type string
 */
char *get_boundary(char *content_type);

/**
 * free an string
 */
int freestring(void *str);


/*
rfc2822eml parser_mail(const char *mail){
    map_t map;
    
    map=hashmap_new();
    
    return map;
}
*/

//Parser the parts of an email (headerName,headerContent and Body) and store them in a hashmap.
rfc2822eml parser_mail(const char *mail){
    char *start_pointer;
    //char *end_pointer;
    int count;
    int status;
    int body_length;

    char *headerN=NULL;
    char *headerCont=NULL;
    map_t map;
    
    linklist *list_received;
    char *headerRaw=NULL;
    char *bodyRaw=NULL;
    char *fullRaw=NULL;
    
    //Variables used in body multipart identification
    linklist *list_parts;
    char *part_type=NULL;
    char *boundary=NULL;
    char *new_boundary=NULL;
    char *new_type=NULL;
    char *body_end=NULL;
    stack *boundary_stack=NULL;
    mime_part *part;
    map=hashmap_new();
    list_received=newlinkedlist();

    //printf("Parsermail is called\n");
    //Inicialization
    count=0;

    status=STATUS_HEADERNAME;

    start_pointer=mail;
    
    if (start_pointer[0]=='\0')
       wblprintf(LOG_WARNING,"EML PARSER","Email content is void\n");

    //end_pointer=start_pointer + strlen(start_pointer);
    
    while(start_pointer[count] != '\0'){
        //It is a header name
        if(status==STATUS_HEADERNAME && (start_pointer[count]!=':')){
            count++;
        }else if (status==STATUS_HEADERNAME && (start_pointer[count]==':')) {
                //printf("End of headername in %d\n",count);
                headerN=(char *)malloc(sizeof(char)*(count+1));
                
                //Copy the headername to the appropiate variable
                memcpy(headerN,start_pointer,count*sizeof(char));
                headerN[count]='\0';
                //printf("+ %s ->", headerN);
                
                if (start_pointer[count+1]=='\0' || start_pointer[count+2]=='\0'){
                    wblprintf(LOG_WARNING,"EML PARSER","Abnormal header termination"); 
                    break;	
                }
				
                start_pointer=&start_pointer[count+2];
                status=STATUS_HEADERCONTENT;
                count=0;
                //It is a header content.
                
         }else if (status==STATUS_HEADERCONTENT && (start_pointer[count]!='\n' || 
              (start_pointer[count]=='\n' && (start_pointer[count+1]=='\t' || start_pointer[count+1]==' '))
              //|| ((start_pointer[count]=='\n') && (start_pointer[count+2]=='\t' || start_pointer[count+2]==' '))
              )){
                 count++;
                 //printf(".");
                }else if(status==STATUS_HEADERCONTENT && (start_pointer[count]=='\n') && 
                         ((start_pointer[count+1]!='\n')  && (start_pointer[count+1]!='\r'))
                      ){
                             headerCont=(char *)malloc(sizeof(char)*(count+1));

                             //strcpy(headerCont,start_pointer);
                             memcpy(headerCont,start_pointer,sizeof(char)*count);
                             headerCont[count]='\0';
                             printf(" +> HEADER: %s -> %s\n", headerN, headerCont);
                             if(!strcmp(headerN,RECEIVED_HEADER)){
                                 //printf(" + RECEIVED_HEADER: %s -> %s\n", headerN, headerCont);
                                 free(headerN);
                                 addendlist(list_received,headerCont);
                                 //countHeader++;
                             }
                             else{ 
                                 //printf(" + NORMAL_1: %s -> %s\n", headerN,headerCont);
                                 //DAVID -> QUE PASA SI ESTÁN REPETIDOS??
                                 char *headerC;
                                 if(hashmap_get(map,headerN,(any_t*)&headerC)==MAP_MISSING){             
                                     //countNormal++;
                                     hashmap_put(map, headerN, headerCont);
                                 }else{
                                     //printf(" $ %s ->%s\n",headerN, headerC);
                                     free(headerCont);
                                     free(headerN);
                                 }                   
                             }

                             status=STATUS_HEADERNAME;
                             start_pointer=&start_pointer[count+1];
                             count=0;
                             //start_pointer+=(count + 1);
                        }else 
                            if(status==STATUS_HEADERCONTENT && ( (start_pointer[count]=='\n' 
                               && start_pointer[count+1]=='\n') || 
                               (start_pointer[count]=='\n' && start_pointer[count+1]=='\r' 
                               && start_pointer[count+2]=='\n'))
                             ){
					 
                                status = STATUS_BODY;
                                //printf("In body, status is %d\n",status);
                                char *headerCont=(char *)malloc(sizeof(char)*count+1);    
                                //Optimize
                                memcpy(headerCont,start_pointer,count*sizeof(char));
                                headerCont[count]='\0';
                                printf(" +< HEADER: %s -> %s\n", headerN, headerCont);
                                if(!strcmp(headerN,RECEIVED_HEADER)){
                                  addendlist(list_received,headerCont);
                                  free(headerN);
                                  //countHeader++;
                                }
                                else{ 
                                    //DAVID -> QUE PASA SI ESTÁN REPETIDOS??
                                    //printf(" + NORMAL_2: %s -> %s\n", headerN,headerCont);
                                    char *headerC;
                                    if(hashmap_get(map,headerN,(any_t*)&headerC)==MAP_MISSING){             
                                        //countNormal++;
                                        hashmap_put(map, headerN, headerCont);
                                    }else{
                                        //printf(" $ %s ->%s\n",headerN, headerC);
                                        free(headerCont);
                                        free(headerN);
                                    } 
                                }

                                hashmap_put(map,RECEIVED_HEADER, list_received);

                                //Restore the status
                                start_pointer=&start_pointer[count];

                                //Copy the header raw
                                headerRaw=malloc((start_pointer-mail+1)*sizeof(char));
                                memcpy(headerRaw,mail,(start_pointer-mail)*sizeof(char));
                                headerRaw[start_pointer-mail]='\0';
                                hashmap_put(map,HEADER_PART,headerRaw);

                                //Copy the body raw
                                start_pointer=&start_pointer[2];
                                body_length=strlen(start_pointer);
                                bodyRaw=malloc(body_length*(sizeof(char)+1));
                                memcpy(bodyRaw,start_pointer,body_length*sizeof(char));
                                bodyRaw[body_length]='\0';
                                hashmap_put(map,BODY_PART,bodyRaw);

                                //Copy full message raw
                                fullRaw=malloc((body_length+start_pointer-mail+2)*sizeof(char));
                                memcpy(fullRaw,mail,(body_length+start_pointer-mail+1)*sizeof(char));
                                fullRaw[(body_length+start_pointer-mail+1)]='\0';
                                hashmap_put(map,FULL,fullRaw);

                                break;
                            }else {
                                wblprintf(LOG_WARNING,"EML PARSER","Status not recognized: status=%d, start_pointer=%s\n", status, start_pointer); 
                                break;				   
                            }
    }
    
    if (status != STATUS_BODY){
        //printf("after that, status is %d\n",status);
        wblprintf(LOG_WARNING,"EML PARSER","Email body not found. Double carriage return not found.\n"); 
        
        linklist *aux;
        if(hashmap_get(map,RECEIVED_HEADER,(any_t*)&aux)==MAP_MISSING){
            freelist((linklist *)list_received,&free_linklist_content_string);
        }
        return map;		
    }
    //finally lets identificate message body parts.
    if (bodyRaw==NULL){
        wblprintf(LOG_WARNING,"EML PARSER","Body has not been parsed due to previous errors.\n"); 
        return map;
    }
    list_parts= newlinkedlist();		
    body_end=bodyRaw+body_length-1;
    
    if (hashmap_get(map, CONTENT_TYPE_HEADER, (any_t *)&part_type)==MAP_OK && 
        is_multipart(part_type) && (boundary=get_boundary(part_type))!=NULL){
        
	start_pointer=bodyRaw;
        //boundary=get_boundary(part_type);
        //printf("BOUNDARY_STACK PUSH: %s\n",boundary);
        boundary_stack=newstack();
        push_item(boundary_stack, boundary);
    
        while(peek_item(boundary_stack,(element *)&boundary)!=STACK_EMPTY && 
              start_pointer<body_end){
	    int boundary_length=strlen(boundary); //Search for the begining of a part
	    char *searching=malloc((boundary_length+3)*sizeof(char));
	    searching[0]=searching[1]='-';
	    memcpy(&(searching[2]),boundary,boundary_length);
	    searching[boundary_length+2]='\0';
	    //printf("boundary: %s, seaching: %s\n", boundary, searching);
	    start_pointer=strstr(start_pointer,searching);
	    if(start_pointer==NULL){
		wblprintf(LOG_WARNING,"EML PARSER","Email is not well-formed\n");
		//NOEEEEEEEEEEEEEEEEEEEE
		free(searching);
		searching=NULL;
		//free(boundary);
		start_pointer=body_end;
		break;
	    }
	    ////AKIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIII
	    start_pointer+=(boundary_length+2);
	    
	    while (start_pointer[0]=='\n' || start_pointer[0]=='\r') start_pointer++;
	    
	    status=STATUS_PART_TYPE;
	    count=0;
	    
	    while(start_pointer < body_end){
		if(status==STATUS_PART_TYPE && (start_pointer[count] != '\n' || 
		   (start_pointer[count] == '\n' && start_pointer[count+1] != '\n'))){
			  count++;
		}else if ((status==STATUS_PART_TYPE && start_pointer[count] == '\n' && start_pointer[count+1] == '\n') ||
		   (status==STATUS_PART_TYPE && start_pointer[count] == '\n' && start_pointer[count+1] == '\r' && start_pointer[count+2] == '\n')){
		    new_type=malloc(sizeof(char)*(count+1));
		    memcpy(new_type,start_pointer,count);
		    new_type[count]='\0';
		    		    
		    start_pointer+=(count+2);
		    
		    if(is_multipart(new_type)){
			new_boundary=get_boundary(new_type);
                        //printf("BOUNDARY_STACK PUSH: %s\n",new_boundary);
			push_item(boundary_stack, new_boundary);
			//NOEMI AÑADI FREEEEE
			free(new_type);
			break;
		    }else{
			char *new_part;
			char *end_part=strstr(start_pointer,searching);
			if (end_part==NULL){
			    wblprintf(LOG_WARNING,"EML PARSER","Email is not well-formed\n");
			    start_pointer=body_end;
			    free(new_type);
			    break;
			}
		      
			int content_length=end_part-start_pointer;
			new_part=malloc(sizeof(char)*(content_length+1));
			memcpy(new_part,start_pointer,content_length);
			new_part[content_length]='\0';
			
			//push the part into the part_list
			//start_pointer and content_length
			//new_type is the content type
			//printf("\n================== PART ==================\n");
			//printf("%s\n\n", new_type);
			//printf("%s", new_part);
			part=malloc(sizeof(mime_part));
			part->header=new_type;
			part->content=new_part;
			addendlist(list_parts,part);
			//printf("\n================ END PART ================\n");
			
			start_pointer += (content_length + boundary_length + 2);
			if (start_pointer<body_end && start_pointer[0]=='-' && start_pointer[1]=='-'){ //The multipart part has ended
			    pop_item(boundary_stack,(element *) &boundary);
			    free(boundary);
			    boundary=NULL;
			    break;
			}else{
			    while (start_pointer[0]=='\n' || start_pointer[0]=='\r') start_pointer++;
			    count=0;
			    status=STATUS_PART_TYPE;
			}
			
		  }
		}
	  }	 
	 free(searching);
	}	
        //printf("ANTES DE FREESTACK TAM:%d\n",getlengthstack(boundary_stack));
	free_stack(boundary_stack,freestring);
        boundary_stack=NULL;
        //printf("DESPUES DE FREESTACK TAM:%d\n",getlengthstack(boundary_stack));
	hashmap_put(map,PARTS,list_parts);
    }else{ 
        if(is_multipart(part_type) && boundary==NULL) 
            wblprintf(LOG_WARNING,"EML_PARSER","Unable to find boundary. Incorrect multipart format\n");
        hashmap_free(list_parts);
        list_parts=NULL;
        
    }
    
    if (boundary_stack!=NULL){ //If parts, then free the stack and add the parts to the parse_map 
	free_stack(boundary_stack,freestring);
        hashmap_put(map,PARTS,list_parts);
    }
	
    //printf("End of multipart parsing...\n");
    
/*
    printf("      Header_mallocs %d\n",countHeader);
    printf("      Normal_mallocs %d\n",countNormal);
    printf("---------------------------------------\n");
    printf("       Total_mallocs %d\n\n",countTotal);
*/
    return map;
    
}

int freestring(void *str){
    free(str);
    return STACK_OK;
}

/**
 * Return the boundary from a content_type string
 */
char *get_boundary(char *content_type){
    char *start_pointer;
    int boundary_length;
    char *returnvalue=NULL;
    int boundary_delimiter=BOUNDARY_EQUALS;

    if( (start_pointer=strstr(content_type,BOUNDARY))==NULL){
        wblprintf(LOG_WARNING,"EML_PARSER","Boundary not found\n");
        return start_pointer;
    }
    start_pointer+=8;
    for(;start_pointer[0]!='"' && start_pointer[0]!='=' && start_pointer[0]!='\0';start_pointer++); //Search the begin of the boundary
    
    if(start_pointer[0]=='\0'){ 
        wblprintf(LOG_WARNING,"EML_PARSER","Unable to find the beginning of the boundary\n");
        return NULL;
    }
    start_pointer++;
    
    if(start_pointer[0]=='"'){
        start_pointer++;
        boundary_delimiter=BOUNDARY_QUOT;
    }
    
    //Now start_pointer contains the pointer to the first character of the boundary

    boundary_length=0; //Now compute the length of the boundary
    if(boundary_delimiter==BOUNDARY_QUOT){
        for(;start_pointer[boundary_length]!='"';boundary_length++);
        
        if(start_pointer[boundary_length]=='\0'){
            wblprintf(LOG_WARNING,"EML_PARSER","Unable to find the end of the boundary. Incorrect format\n");
            return NULL;
        }
        
        returnvalue=malloc(sizeof(char)*(1 + boundary_length));
        memcpy(returnvalue,start_pointer,boundary_length);
        returnvalue[boundary_length]='\0';
    }else{
        for(;start_pointer[boundary_length]!='\n';boundary_length++);
        
        if(start_pointer[boundary_length]=='\0'){
            wblprintf(LOG_WARNING,"EML_PARSER","Unable to find the end of the boundary. Incorrect format\n");
            return NULL;
        }
        
        returnvalue=malloc(sizeof(char)*(1 + boundary_length));
        memcpy(returnvalue,start_pointer,boundary_length);
        returnvalue[boundary_length]='\0';
    }
    
    return returnvalue;
}

/**
 * Return true if content type is multipart
 */
int is_multipart(char *content_type){
    //DAVID. SI CONTENT TYPE ES NULL. STRSTR PETA!!
    if(content_type==NULL) return 0;
    else return (strstr(content_type,MULTIPART_KEYWORD)!=NULL);
}

int free_linklist_content_string(element data){
    //printf(" - HEADER -> %s\n",(char *)data);
    //uncountHeader++;
    free((char *)data);
    return NODE_OK;
}

int free_linklist_content_body_part(element _data){
    mime_part *data=_data;

    free(data->header);
    free(data->content);
    free(data);
    
    return NODE_OK;
}

int free_parsed_content(any_t item, any_t data, any_t key){
    //printf("Key %s\n",(char *)key);
    
    if (//strcmp((char *)key,BODY_PART) && strcmp((char *)key,HEADER_PART) &&
        strcmp((char *)key,RECEIVED_HEADER) && strcmp((char *)key,RAW_ENTRY)
        && strcmp((char *)key,PARTS) && strcmp((char *)key,MUTEX_EML)
        //&& strcmp((char *)key,FULL)
        ){
        //printf(" - headerC: '%s'\n",(char *)data);
        free((char *)data);
    }
    else if(!strcmp((char *)key,RECEIVED_HEADER)){
        freelist((linklist *)data,&free_linklist_content_string);
    }else if (!strcmp((char *)key, PARTS)){
        freelist((linklist *)data,&free_linklist_content_body_part);
    }
    
    if (strcmp((char *)key,BODY_PART) && strcmp((char *)key,HEADER_PART) &&
        strcmp((char *)key,RECEIVED_HEADER) && strcmp((char *)key,RAW_ENTRY) 
        && strcmp((char *)key,FULL) && strcmp((char *)key,PARTS) 
        && strcmp((char *)key,RAW_TEXT) && strcmp((char *)key,MUTEX_EML)
        ){
        //printf(" - NORMAL: '%s'\n",(char *)key);
        //uncountNormal++;
        free((char *)key);
    }
    return MAP_OK;
}

void free_mail(rfc2822eml eml){
    if(eml!=NULL){
        hashmap_iterate_elements(eml, &free_parsed_content, NULL);
        hashmap_free(eml);
        eml=NULL;
    }
}

int compileTextParts(void *d, element e){
	char **_ret_value=d;
	char *ret_value=*_ret_value;
	
	mime_part *part=(mime_part *)e;
	//printf(".\n");
	//printf("header: %s\n",part->header);
	if (strstr(part->header,"text/html")!=NULL){
		//printf("xx\n");
		//printf("%s\n",part->content);
		char *dumped=dumpHTMLtext(getDefaultHTMLdumper(),part->content);
		//printf("%s\n", dumped);
		ret_value=appendstr(ret_value,dumped);
		free(dumped);
		//printf("yy\n");
		*_ret_value=ret_value;
	}else if (strstr(part->header,"text/")!=NULL){
		//printf("a part with type text/*\n");
		ret_value=appendstr(ret_value,part->content);
		*_ret_value=ret_value;
	}
	
	return NODE_OK;
}

char *dump_text(rfc2822eml eml){
	char *part_type=NULL;
	char *body=NULL;
	char *ret_value=NULL;
	pthread_mutex_t *mutex4eml;
	int use_concurrent=1;

	if (hashmap_get(eml,MUTEX_EML,(any_t *) &mutex4eml)==MAP_OK){
	   pthread_mutex_lock(mutex4eml);
           use_concurrent=1;
        }
	else use_concurrent=0;

	if (hashmap_get(eml, RAW_TEXT, (any_t *)&ret_value)==MAP_OK){
            if (use_concurrent) pthread_mutex_unlock(mutex4eml); //ADDED DAVID
            return ret_value;
	}
	
	if (hashmap_get(eml,CONTENT_TYPE_HEADER, (any_t *)&part_type)==MAP_OK && is_multipart(part_type)){
                linklist *listparts=NULL;
                if(hashmap_get(eml,PARTS,(any_t *)&listparts)==MAP_OK){
                    ret_value=malloc(sizeof(char));
                    ret_value[0]='\0';
                    linklist_iterate_data(listparts,&compileTextParts, &ret_value);
                }else{
                    printf("ES UN MULTIPART PERO EL BOUNDARY NO LO ENCUENTRA\n");
                }
                hashmap_put(eml,RAW_TEXT,ret_value);
	}else{
            if (hashmap_get(eml, BODY_PART, (any_t *)&body)==MAP_OK){
                int body_length=strlen(body);
                ret_value=malloc(sizeof(char)*(body_length+1));
                memcpy(ret_value,body,body_length+1);
                hashmap_put(eml,RAW_TEXT,ret_value);
            }
	}
	
	if (use_concurrent) pthread_mutex_unlock(mutex4eml);

	return ret_value;
}

void freeEMLParser(){
    freeDefaultHTMLdumper();
}

//All lines in eml text parts end in =\n and 
//When =hh (where hh are two hex digits) the
//character should be replaced by the corresponding 
//charset code.
//char * post_process_eml_text_part(char *eml){
//	char *eml;
//}

char *getHeaderContent(rfc2822eml eml, const char *header ){
    char *ret_val;
    if (hashmap_get(eml,(map_t)header, (any_t *)&ret_val)==MAP_OK)
       return ret_val;
    else return NULL;
}

//void printfValues(){
//    printf("      Header_mallocs %d\n",countHeader);
//    printf("      Normal_mallocs %d\n",countNormal);
//    printf("---------------------------------------\n");
//    printf("       Total_mallocs %d\n\n",countHeader+countNormal);
    
//    printf("      Header_frees %d\n",uncountHeader);
//    printf("      Normal_frees %d\n",uncountNormal);
//    printf("---------------------------------------\n");
//    printf("       Total_frees %d\n\n",uncountHeader+uncountNormal);
//    
//    printf("Total balance [mallocs vs frees] %d\n",(countHeader+countNormal)-(uncountHeader+uncountNormal));
    
//}