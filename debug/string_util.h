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
#ifndef _STRING_UTIL_H__
#define _STRING_UTIL_H__

/**
 * Append a char to an string
 */
char *append(char* s, char c);

/**
 * Remove spaces at the end and start of an string
 */
char* trim(char* b);

/**
 * Append a string to another string
 */
char *appendstr(char* s, char *c);

/**
 *  Remove all spaces from a string 
 */
char *remove_spaces_and_lower(char *b);

#endif
