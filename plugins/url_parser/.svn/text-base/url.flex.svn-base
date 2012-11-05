/***************************************************************************                        
*
*   File    : url.flex
*   Purpose : Implements a flex parser to find URLs in an eml file
*            
*   Author: Noemi Perez, David Ruano, Jose Ramon Mendez
* 
* 
*   Date    : October  30, 2010
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

%option noyywrap

%{
#include "list.h"
#include <string.h>
#include <stdlib.h>
#include "trim.h"
%}

	List url_list;
	char *one_url=NULL;
	int all_size_urls=0;

PROT	("http"|"ftp"|"ssh"|"https")
%%

[:blank:]*{PROT}:\/\/[^[:blank:]]*[:blank:]*	{
                char *tmpcad=malloc(sizeof(char)*strlen(yytext)+1);
                strcpy(tmpcad,yytext);
                tmpcad=trim(tmpcad);
		one_url=malloc(sizeof(char)*strlen(tmpcad)+1);
		strcpy(one_url,tmpcad);
		Insert(one_url,url_list,Header(url_list));
		all_size_urls+=strlen(tmpcad);
		free(tmpcad);
		all_size_urls+=1;
        }
\"{PROT}:\/\/[^[:blank:]]*\"	{
		one_url=malloc(sizeof(char)*strlen(yytext)-1);
		strncpy(one_url,yytext+1,strlen(yytext)-2);
		Insert(one_url,url_list,Header(url_list));
		all_size_urls+=strlen(yytext);
		all_size_urls+=1;
	}
.	{
	}
\n	{
	}
%%

/**
 * Init parser
 */
void lex_url_parser_init(){
        all_size_urls=0;
	url_list=MakeEmpty(NULL);
}

/**
 * Make a string with the text collected
 */
char *lex_url_parser_get_as_string(){
      char *retval;
      Position p;

      retval=malloc(sizeof(char)*all_size_urls+1);
      strcpy(retval,"");
      p=Header(url_list);
      if (!IsEmpty(url_list))
	do {
           p = Advance(p);
           strcat(retval,(char *)Retrieve(p));
           if (!IsLast(p, url_list)) strcat(retval,"\n");
        }while (!IsLast(p,url_list));
      return retval;
}

void lex_url_parser_flex_destroy(){
      Position p;

      p=Header(url_list);
      if (!IsEmpty(url_list))
        do {
           p = Advance(p);
           free (Retrieve(p));
        }while (!IsLast(p,url_list));
      DeleteList(url_list);
}

char *lex_url_parser_parse_string(const char *str){
    char *ret_val;

    lex_url_parser_init();
    yy_scan_string(str);
    flex_url_parserlex();
    ret_val=lex_url_parser_get_as_string();
    lex_url_parser_flex_destroy();
    return ret_val;
}

