/***************************************************************************                        
*
*   File    : string_util.h 
*   Purpose : 
*            
*   Original Author: Ivan Paz, Jose Ramon Mendez (from Grindstone project)
* 
*   New Funcitons included by Jose Ramon Mendez
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

#include "string_util.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include "logger.h"

/*Append a char to a string*/
char *append(char* s, char c){
    char *tmp;
    int len=strlen(s);

    if ((tmp=(char *)realloc(s, (len+2)*sizeof(char)))==NULL){
      wblprintf(LOG_WARNING,"STRING_UTIL","Imposible to make a realloc\n");
      tmp=(char *)malloc((len+2)*sizeof(char));
      strcpy(tmp,s);
      free(s);
    }
    s=tmp;

    s[len]=c;
    s[len+1]='\0';

    return s;
}

/* Append a string to another one */
char *appendstr(char* s, char *c){
    char *tmp;

    if ((tmp=(char *)realloc(s, (strlen(s)+strlen(c)+1)*sizeof(char)))==NULL){
      wblprintf(LOG_WARNING,"STRING_UTIL","Imposible to make a realloc\n");
      tmp=(char *)malloc((strlen(s)+strlen(c)+1)*sizeof(char));
      strcpy(tmp,s);
      free(s);
    }
    s=tmp;

    strcat(s,c);

    return s;
}

/* Remove spaces from begining and end of an string */
char* trim(char* b){
  char* e=strrchr(b, '\0'); /* Find the final null */
  while(b<e && isspace(*b)) /* Scan forward */
    ++b;
  while (e>b && isspace(*(e-1))) /* scan back from end */
    --e; 
  *e='\0'; /* terminate new string */
  return b;
}

inline char lower(char input){
	if (input >= 'A' && input <= 'Z') return  input=input - 'A' + 'a';
	else return input;
}

char *to_lower_case(char *string){
    int i=0;
    for(;i<strlen(string);i++){
        string[i]=tolower(string[i]);
    }
    return string;
}

/* Remove all spaces from a string */
char *remove_spaces_and_lower(char *b){
	char *write_pointer;
	char *read_pointer;
	
	read_pointer=b;
	write_pointer=b;
	
	while (read_pointer[0]!='\0'){
		if (read_pointer[0]==' ' || read_pointer[0]=='\t' || read_pointer[0]=='\n' || read_pointer[0]=='\r'){
			read_pointer++;
		}else{
			   write_pointer[0]=lower(read_pointer[0]);
			   write_pointer++;
			   read_pointer++;
		}
	}
	write_pointer[0]='\0';
	
	return b;
}
