/***************************************************************************
*
*   File    : logger.h
*   Purpose : Header file need for list conf logs.
*
*
*   Author  : David Ruano Ordas
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

#ifndef __LOGGER_H__
#define __LOGGER_H__

#define DEFAULT_LOG_LEVEL 3
#define LOG_CRITICAL 1
#define LOG_WARNING 2
#define LOG_INFO  3
#define LOG_DEBUG  4

void set_log_level(int level);

int get_log_level();

//void wblprintf(const int level,const char * module, const char * args,...);

void wblprintf(const int level,const char* module,char *fmt,...);

void wblfprintf(char *file, const int level,const char* module, char *fmt,...);

#endif
