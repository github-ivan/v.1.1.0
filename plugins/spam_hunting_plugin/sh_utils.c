/***************************************************************************
*
*   File    : spamhunting_plugin.c
*   Purpose :
*
*
*   Author  : Noemí Pérez Díaz
*   Date    : April  1, 2011
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
#include <db.h>
#include "learn_spamhunting.h"
#include "logger.h"
#include "hashmap.h"
#include "tokenize.h"
#include "linked_list.h"
#include "linkedhashmap.h"
#include "sh_utils.h"
#include "db_utils.h"

#define RELEVANCE_AMOUNT 0.5

struct info{
    tokensdata *magic;
    DB *tokensdb;
    DB *map_tokens;
    int *count_tokens;
    long double allrelevance;
};

typedef struct info info;

struct reltok{
    char *token;
    double rel;
};

typedef struct reltok reltok;

struct maxemail{
    int *max;
    linklist *email;
};

typedef struct maxemail maxemail;

int compare_rel (element a, element b){
    if (((reltok *)a)->rel < ((reltok *)b)->rel){
        return -1;
    }
    else if (((reltok *)a)->rel > ((reltok *)b)->rel)
            return 1;
         else return 0;
}

int compare_occurrence(element a, element b){
    messageoccur *a1=(messageoccur *)a;
    messageoccur *b1=(messageoccur *)b;
    if(a1->occurrences>b1->occurrences)
        return -1;
    else
        if(a1->occurrences<b1->occurrences)
            return 1;
        else
            return 0;
}

long double calc_relevance(int count_token, info *info, tokensdata *tok){
    long double rel=0;

    long double nspam,nham,toks,tokh;

    nspam=(long double)info->magic->spam_count;
    nham=(long double)info->magic->ham_count;

    toks=(long double)tok->spam_count;
    tokh=(long double)tok->ham_count;

    //printf("Número de tokens %Lf\n",(long double)*info->count_tokens);
    //printf("Veces del token %Lf\n",(long double)count_token);
    //printf("Mensajes ham %Lf\n",nham);
    //printf("Mensajes spam %Lf\n",nspam);
    //printf("Spam del token %Lf\n",toks);
    //printf("Ham del token %Lf\n",tokh);

    rel=((long double)count_token / (long double)*info->count_tokens) *
         (((nspam/(nspam+nham)) * (toks/(toks+tokh)) +
         (nham/(nspam+nham))*(tokh/(toks+tokh))) /
         ((toks+tokh)/(nspam+nham)));
    //printf("RELEVANCIA PARCIAL %Lf\n",rel);   
    //printf("Relevancia %Lf\n",rel);
    return rel;
}

int relevance(any_t relevant_list, any_t inf, any_t tokens){
    if (strcmp((char *)tokens,MAGIC_TOKEN) && strcmp((char *)tokens,COUNT_TOKEN)){
        tokensdata *tok;
        reltok *rt=(reltok *)malloc(sizeof(reltok));
        long double rel=0.0;
        info *info;
        info=inf;
        int *count_token;

        //Número de veces que se repite el token ->count_token
        hashmap_get(info->map_tokens,tokens,(any_t *)&count_token);
        //printf("TOKEN %s->Número de veces que se repite %i\n",(char *)tokens,*count_token);
        if ((tok=(tokensdata *)malloc(sizeof(tokensdata)))!=NULL){
            if(get_data_token_sh(info->tokensdb,(char *)tokens,tok)==TOKEN_MISSING){
                rel=((long double)*count_token)/((long double)*info->count_tokens);
                //printf("Token %s \n",(char *)tokens);
                //printf("Esta el token \n");
            }else{
                //printf("Token %s \n",(char *)tokens);
                // if (strcmp((char *)tokens,MAGIC_TOKEN))// && strcmp((char *)tokens,COUNT_TOKEN))
                rel=calc_relevance(*count_token,info,tok);
            }
            //printf("RELEVANCIA!!!->>%Lf\n",rel);
            rt->token=(char *)tokens;
            rt->rel=rel;
            info->allrelevance+=rel;
            //printf("ALL RELEVANCE %Lf\n",info->allrelevance);
            addorder(relevant_list,rt,&compare_rel);
            free(tok); //DAVID. 
            return MAP_OK;
        }
        return MAP_MISSING;
    }
    return MAP_OK;
}
/*
int printlist(element item, element data)
{
    messageoccur *aux=(messageoccur* )data;
    printf("LISTA message id %s\n",(char *)aux->message_id);
    printf("LISTA Ocurrence %d\n",aux->occurrences);
    return NODE_OK;
}
*/

int cal_max(element max, element data){
    messageoccur *aux=(messageoccur *)data;
    //printf("OCCURRENCIA DE LA LISTA %d\n",aux->occurrences);
    //printf("MAX %d\n",*((int *)max));
    if(*((int *)max)<aux->occurrences)
        *(int *)max=aux->occurrences;
    return NODE_OK;
}

int del_min(element maxmail, element data){
    messageoccur *aux=(messageoccur *)data;
    maxemail *auxmail=(maxemail *)maxmail;
    linklist *list=(linklist *)auxmail->email;
    int max=*(int *)(auxmail->max);

    if(aux->occurrences==max){
        addendlist(list, (element)aux);
        //printf("Ocurrencia añadida %d\n",aux->occurrences);
    }
        
    return NODE_OK;
}

int free_node(element data){
    free((reltok*)data);
    return NODE_OK;
}

int free_lh_key(any_t item, any_t key){
    free(key);
    return MAP_OK;
}

int free_lh_data(any_t data){
    messageoccur *moc=((messageoccur *)data);
    free(moc);
    return MAP_OK;
}

int free_d(element data){
    return NODE_OK;
}
//int linklist_iterate_three(linklist *list, PFunction f, element item, element item2, element item3, elemt item4)
//f(item4, item3, item2, item, data);
//linklist_iterate_three(relevant_list, &createListEmails, inf->allrelevance, pairs,listemails, accrelevance)
/*
int createListEmails(any_t data4 ,any_t data3, any_t data2, any_t data1, any_t key){
    if(()data1*RELEVANCE_AMOUNT>()data4){
        data4+=key->rels;
        get_data_pairs_sh(,rels->token, &listemails);
    }
    if(inf->allrelevance*RELEVANCE_AMOUNT>accrelevance){
        accrelevance+= rels->rel;
        get_data_pairs_sh(pairs,rels->token, &listemails);
        return MAP_OK;
    }
    else return MAP_MISSING;
}
*/
int scan_sh(char *mail, spamhunting_db *databases){
    DB *tokens;
    DB *email;
    DB *pairs;

    tokens=databases->tokensdb;
    email=databases->emaildb;
    pairs=databases->pairsdb;
    
    int *count_tokens; //Total number of email tokens
    map_t map_tokens; //Email tokens
    
    map_tokens=tokenize(mail);
    
    if (hashmap_get(map_tokens,COUNT_TOKEN,(any_t *)&count_tokens)==MAP_MISSING){
        wblprintf(LOG_WARNING,"SPAMHUNTING: ", "E-mail not contains tokens.\n");
        free(count_tokens);
        return -1;
    }
    //printf("Número de tokens en el mail %i\n",*count_tokens);

    tokensdata *magic; //Magic_token contains number of spam/ham messages
    
    magic=(tokensdata *)malloc(sizeof(tokensdata));

    if (get_data_token_sh(tokens,MAGIC_TOKEN,magic) == TOKEN_MISSING){
	   wblprintf(LOG_WARNING,"SPAMHUNTING ", "Tokens Database is empty.\n");
	   free(magic);
       return -1;
    }
    //printf("MAGIC TOKEN %i\n",magic->ham_count);
    
    info *inf;
    inf=(info *)malloc(sizeof(info));
    inf->magic=magic;
    inf->count_tokens=count_tokens;
    inf->tokensdb=tokens;
    inf->map_tokens=map_tokens;
    inf->allrelevance=0;

    //List ordered by relevance. Contains reltok(token, prob).
    linklist *relevant_list=newlinkedlist();
    //SE obtiene la lista de los tokens del mensaje ordenada de mayor a menor relevancia.
    hashmap_iterate_three(map_tokens,&relevance,inf, relevant_list);
    long double accrelevance=0.0;

    if (getlengthlist(relevant_list)==0){
        wblprintf(LOG_CRITICAL,"BAYES ","Cannot use bayes on this message; not enough usable tokens found\n");
        return -1;
    }
    int i=0;
      
    linkedhashmap *listemails=newlinkedhashmap();
    
    reltok *rels;
    //linklist_iterate_three(relevant_list, &createListEmails, inf->allrelevance, pairs,listemails)
    
    while( i<getlengthlist(relevant_list) && inf->allrelevance*RELEVANCE_AMOUNT>accrelevance){
        
        getatlist(relevant_list,i,(void *)&rels);//MIRAR SOLUCIONAR CON ITERADOR
        //Va sumando la relevancia de los tokens de mas relevancia.
        accrelevance+= rels->rel;
        //printf("ACCRELEVANCE %Lf\n",accrelevance);
        //printf("LONGITUD %d\n",getlengthlist(relevant_list));
        //Introduce en un linked hashmap una estructura messageoccur(char *message_id, int ocurrences)
        get_data_pairs_sh(pairs,rels->token, &listemails);
        //printf("Tamaño lISTEMAILS! %d\n",get_lh_size(listemails));
        i++;
        //printf("I: %i\n",i);
    }

    //linklist_bubble_sort(listemails,&compare_occurrence);
    //Ordered contiene una lista con messageoccur(message_id,occurrences)
    linklist *ordered=lh_getlist(listemails);
    //printf("Tamaño lista de message id y occurs %d\n",getlengthlist(ordered));
    //printf("Tamaño linked_hashmap %d\n",get_lh_size(listemails));
    //linklist_bubble_sort(ordered,&compare_occurrence);//AÑADIDO PARA PRUEBAS
    //linklist_iterate_data(ordered, &printlist, NULL);
    //AÑADIDO EN LUGAR DE BUBBLESORT
    int *max_value = malloc(sizeof(int));
    *max_value=0;
    linklist_iterate_data(ordered, &cal_max, (element)max_value);
    //printf("MAX %d\n",*((int *)max_value));

    maxemail *maxmail =malloc (sizeof(maxemail));
    maxmail->email=newlinkedlist();
    maxmail->max=max_value;
    linklist_iterate_data(ordered, &del_min, (element)maxmail);
    //printf("Emails que votan %d\n",getlengthlist(maxmail->email));
    //AÑADIDO EN LUGAR DE BUBBLESORT, SE CAMBIA ordered POR email
    //element max,aux;
    element aux;
    int j=0;
    //getfirst(maxmail->email,(element *)&max);
    int spamcount=0;
    int hamcount=0;
    //printf("MAXIMO %d\n",((messageoccur *)max)->occurrences);
    //getatlist(maxmail->email,j,(element *)&aux);
    int *class=malloc(sizeof(int));
    while(j<getlengthlist(maxmail->email)){//(((messageoccur *)aux)->occurrences==((messageoccur *)max)->occurrences){
        //int *class=malloc(sizeof(int));
        //printf("OCURS DEL MENSAJE %i\n",((messageoccur *)aux)->occurrences);
        //printf("MAX OCURS %i\n",((messageoccur *)max)->occurrences);
        //printf("GET DATA EMAIL %d\n",get_data_email_sh(email,((messageoccur *)aux)->message_id, class));
        getatlist(maxmail->email,j,(element *)&aux);
        
        wblprintf(LOG_INFO, "SPAMHUNTING","MENSAJE QUE VOTA %s\n",(char *)((messageoccur *)aux)->message_id);
        get_data_email_sh(email,((messageoccur *)aux)->message_id, class);
        wblprintf(LOG_INFO, "SPAMHUNTING","CLASE QUE VOTA %d\n",*class);
        (*class==1)?(spamcount++):(hamcount++);
        j++;
        //getatlist(maxmail->email,j,(element *)&aux);
        wblprintf(LOG_INFO, "SPAMHUNTING","Voto ham %d\n",hamcount);
        wblprintf(LOG_INFO, "SPAMHUNTING","Voto spam %d\n",spamcount);
        
        //printf("OCCURENCES %d\n",((messageoccur *)aux)->occurrences==((messageoccur *)max)->occurrences);
    }//while(((messageoccur *)aux)->occurrences==((messageoccur *)max)->occurrences);
    
    free(magic);
    free(class);
    free(inf);
    free(max_value);
    freelist(relevant_list,&free_node);    
    free_tokenize(map_tokens);
    
    freelist(maxmail->email,&free_d);
    free(maxmail);

    //freelist(ordered,&free_d);

    //linklist_iterate_data(lh_getlist(listemails),&free_lh_data,NULL);    
    free_linkedhashmap(listemails,&free_lh_data,&free_lh_key);
    //remove_linkedhashmap(listemails);

    //hashmap_iterate_elements(lh_gethashmap(listemails),&free_d,NULL);
    //freelist(ordered,&free_d);
    //hashmap_iterate_keys(lh_gethashmap(listemails),&free_key,NULL);
    
    //freelist(ordered,&free_data);
    //hashmap_iterate_elements(lh_gethashmap(listemails),&free_data,NULL);
    //linklist_iterate_data(lh_getlist(listemails),&free_d,NULL);
    if (spamcount>0 && hamcount==0) return 1;
    else return 0;
}



/*
int main(){
    char *result;
    ae_load_eml_to_memory("simple.eml",&result);

    //printf("EMAIL%s\n",result);
    printf("RESULTADO %i\n",scan_sh(result));
}*/