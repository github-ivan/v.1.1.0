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

#ifndef _HEADER_PARSER_H_
#define	_HEADER_PARSER_H_

#include "eml_parser.h"

struct received_header;
typedef struct received_header ip_info;

ip_info *get_header_info(rfc2822eml email, int position);
char *get_received_domain(ip_info *info);
char *get_received_ip(ip_info *info);
char *get_from_domain(ip_info *info);
void free_ip(ip_info *info);
void free_parsed_ip(char **ip);
char *get_octect(char **ip,int num);
char **parse_ip(char *ip);
int get_ip_size(char **ip);


#endif	/* HEADER_PARSER_H */
