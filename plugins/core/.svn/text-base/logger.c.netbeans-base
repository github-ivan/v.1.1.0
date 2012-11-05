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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdarg.h>
#include "logger.h"
#include "string_util.h"

int log_level=DEFAULT_LOG_LEVEL;

typedef struct tm datetime;



void set_log_level(int level){
    log_level=level;
}


int get_log_level(){
    return log_level;
}

void wblprintf(const int level,const char* module,char *fmt,...){

    if(log_level>=level){
        datetime *ptr;
        time_t lt;
        lt = time(NULL);
        ptr = localtime(&lt);
    
        char *p, *s,*date;
        va_list argp;
        int i;
        double d;
        long int li;
        char * output=NULL;
        
        va_start(argp, fmt);

        switch(level){
            case LOG_CRITICAL: date=strtok(asctime(ptr),"\n");                               
                               output=malloc(sizeof(char)*strlen(module)+strlen(date)+17);
                               sprintf(output,"[%s] CRITICAL - %s: ",date,module);
                               break;
            case LOG_WARNING:  date=strtok(asctime(ptr),"\n");                               
                               output=malloc(sizeof(char)*strlen(module)+strlen(date)+16);
                               sprintf(output,"[%s] WARNING - %s: ",date,module);
                               break;
            case LOG_INFO:     date=strtok(asctime(ptr),"\n");
                               output=malloc(sizeof(char)*strlen(module)+strlen(date)+13);
                               sprintf(output,"[%s] INFO - %s: ",date,module);
                               break;
            case LOG_DEBUG:    date=strtok(asctime(ptr),"\n");                               
                               output=malloc(sizeof(char)*strlen(module)+strlen(date)+16);
                               sprintf(output,"[%s] DEBUG - %s: ",date,module);
                               break;
        }

        for(p = fmt; *p != '\0'; p++){
            if(*p != '%'){
                output=append(output,*p);
                continue;
            }

            switch(*++p){
                case 'c':
                        i = va_arg(argp, int);
                        output=append(output,i);
                        break;
                case 'd':
                        i = va_arg(argp, int);
                        char *num = malloc(sizeof(int)+sizeof(char));
                        sprintf(num,"%d",i);
                        output=appendstr(output,num);
                        free(num);
                        break;
                case 's':
                        s = va_arg(argp, char *);
                        output=appendstr(output,s);
                        break;
                case 'f':
                        d = va_arg(argp,double);
                        char *doub=malloc(sizeof(double)+sizeof(char));
                        sprintf(doub,"%2.2f",d);
                        output=appendstr(output,doub);
                        free(doub);
                        break;
                case 'l':
                        li = va_arg(argp,long);
                        char *longint=malloc(sizeof(long)+sizeof(char));
                        sprintf(longint,"%ld",li);
                        output=appendstr(output,longint);
                        free(longint);
                        break;
                case '%':
                        output=appendstr(output,"%");
                        break;
            }
        }
        printf("%s",output);
        free(output);
        va_end(argp);
    }
}

void wblfprintf(char *file, const int level,const char* module, char *fmt,...){}
