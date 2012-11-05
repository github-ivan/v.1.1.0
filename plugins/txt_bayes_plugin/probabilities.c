/***************************************************************************
*
*   File    : probabilities.c
*   Purpose :
*
*
*   Author  : Noemí Pérez Díaz
*   Date    : November  16, 2010
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

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "logger.h"
#include "probabilities.h"
#include "linked_list.h"

#define ROBINSON 1
#define HAPAXES 1
#define FW_X_CONSTANT 0.538L
#define FW_S_CONSTANT 0.030L
#define FW_S_DOT_X FW_S_CONSTANT+FW_X_CONSTANT

int prob_no_robinson(int tok_spam,int tok_ham);
int prob_hapaxes(int tok_spam,int tok_ham);
double prob_robinson(int tok_spam,int tok_ham,double prob);
int compare (element a, element b);

double prob_token (char *token, dbinfo *info){//int ns, int nn, int tok_spam, int tok_ham){
     
     //search token in tokens database.
     tokendata *dat;
     double prob; //Probability of spam token

     dat=(tokendata *)malloc(sizeof(tokendata));
     if(get_data_token(info->dbp,token,dat)!=TOKEN_FOUND){
         free(dat);
         return NOT_INFO_AVAILABLE;
     }
     
     //If do not use Robinson
     if (!ROBINSON){
         prob= (prob_no_robinson(dat->spam_count,dat->ham_count));
         free(dat);
         return prob;
     }
     //If do not use HAPAXES
     if (!HAPAXES){
        prob= (prob_hapaxes(dat->spam_count,dat->ham_count));
        free(dat);
        return prob;
     }

     //There are not spam messages or ham messages.
     if (info->magic_token->ham_count==0 || info->magic_token->spam_count==0){
         free(dat);
         return 1;
     }

     double ration=0.0;
     double ratios=0.0;
     ratios=(double)dat->spam_count/(double)info->magic_token->spam_count;
     ration=(double)dat->ham_count/(double)info->magic_token->ham_count;
     
     if (ratios==0.0 && ration==0.0){
         wblprintf(LOG_WARNING,"BAYES:","Spam ratio or ham ratio equals zero");//CAMBIARLOO
         free(dat);
         return NOT_INFO_AVAILABLE;
     }else {
         prob=ratios/(ratios+ration);
         //printf("PROB ANTES DE ROBINSON: %2.55f\n",prob);
     }

     // Use Robinson's f(x) equation for low-n tokens, instead of just ignoring them
     if (ROBINSON){
         prob= (prob_robinson(dat->spam_count,dat->ham_count,prob));
         //printf("PROB BEFORE ROBINSON: %2.55f\n",prob);
     }
     //printf("ANTES DE METERLO TODO %2.2f\n",prob);
     free(dat);
     return prob;
}

int prob_no_robinson(int tok_spam,int tok_ham){
    return (tok_spam+tok_ham<10);
}

int prob_hapaxes(int tok_spam,int tok_ham){
    return (tok_spam+tok_ham<2);
}

double prob_robinson(int tok_spam,int tok_ham,double prob){
    int rob;
    rob=tok_spam+tok_ham;
    return ((FW_S_DOT_X+(rob*prob))/(FW_S_CONSTANT+rob));
}