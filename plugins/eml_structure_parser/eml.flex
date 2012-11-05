/***************************************************************************                        
*
*   File    : eml.flex
*   Purpose : Implements a flex parser to separate header, body and full message
*      from an eml file.
*            
*   Author: David Ruano, Noemi Perez, Jose Ramon Mendez
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

%option noyywrap

%{
#include "list.h"
#include <string.h>
#include <stdlib.h>
%}

	List header_list;
        List body_list;
	char *one_line=NULL;
	int all_size_headers=0;
        int all_size_body=0;
	int end_headers=0;

%%
\n\r*\n	{
		if (!end_headers) end_headers=1;
		else {
			one_line=malloc(sizeof(char)*strlen(yytext)+1);
			strcpy(one_line,yytext);
			Insert(one_line,body_list,Header(body_list));
			all_size_body+=strlen(yytext);
			all_size_body+=1;
		}
	}
[^\n]*	{
		one_line=malloc(sizeof(char)*strlen(yytext)+1);
		strcpy(one_line,yytext);
     
		if (!end_headers){
			Insert(one_line,header_list,Header(header_list));
			all_size_headers+=strlen(yytext);
			all_size_headers+=1;
		}else{
			Insert(one_line,body_list,Header(body_list));
			all_size_body+=strlen(yytext);
			all_size_body+=1;
        }

    }
\n	{
	}
%%

/**
 * Init parser
 */
void lex_structure_parser_init(){
	end_headers=0;
	all_size_headers=0;
	all_size_body=0;
	header_list=MakeEmpty(NULL);
	body_list=MakeEmpty(NULL);
}

/**
 * Make a string with the text collected on headers
 */
char *lex_header_parser_get_as_string(){
      char *retval;
      Position p;

      retval=malloc(sizeof(char)*all_size_headers+1);
      strcpy(retval,"");
      p=Header(header_list);
      if (!IsEmpty(header_list))
	do {
           p = Advance(p);
           strcat(retval,(char *)Retrieve(p));
           if (!IsLast(p, header_list)) strcat(retval,"\n");
        }while (!IsLast(p,header_list));
      return retval;
}

/**
 * Make a string with the text collected on body
 */
char *lex_body_parser_get_as_string(){
      char *retval;
      Position p;

      retval=malloc(sizeof(char)*all_size_body+1);
      strcpy(retval,"");
      p=Header(body_list);
      if (!IsEmpty(body_list))
        do {
           p = Advance(p);
           strcat(retval,(char *)Retrieve(p));
           if (!IsLast(p, body_list)) strcat(retval,"\n");
        }while (!IsLast(p,body_list));
      return retval;
}

void lex_structure_parser_flex_destroy(){
      Position p;

      p=Header(header_list);
      if (!IsEmpty(header_list))
        do {
           p = Advance(p);
           free (Retrieve(p));
        }while (!IsLast(p,header_list));
      DeleteList(header_list);

      p=Header(body_list);
      if (!IsEmpty(body_list))
        do {
           p = Advance(p);
           free (Retrieve(p));
        }while (!IsLast(p,body_list));
      DeleteList(body_list);
}

char *lex_header_parser_parse_string(const char *str){
    char *ret_val;

    lex_structure_parser_init();
    yy_scan_string(str);
    flex_structure_parserlex();
    ret_val=lex_header_parser_get_as_string();
    lex_structure_parser_flex_destroy();
    return ret_val;
}

char *lex_body_parser_parse_string(const char *str){
    char *ret_val;

    lex_structure_parser_init();
    yy_scan_string(str);
    flex_structure_parserlex();
    ret_val=lex_body_parser_get_as_string();
    lex_structure_parser_flex_destroy();
    return ret_val;
}

