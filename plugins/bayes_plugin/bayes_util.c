/* 
 * File:   bayes_util.c
 * Author: drordas
 *
 * Created on 29 de febrero de 2012, 10:37
 */

#include <stdio.h>
#include <stdlib.h>
#include "bayes_util.h"
#include "combinechi.h"
#include "iniparser.h"
#include "db_utils.h"


//INTERNAL VALUES
#define MIN_PROB_STRENGTH 0.346L
#define BAYES_PROB_ERR -1.00

long double scan_mail(char *mail, DB *dbp, bayes_config *config){

    map_t map_tokens=NULL;    
    tokendata *dat=NULL;

    if(mail==NULL){
        wblprintf(LOG_WARNING,"BAYES PLUGIN", "Email not parsed\n");
        return BAYES_PROB_ERR;
    }
    
    dat=(tokendata *)malloc(sizeof(tokendata));
   
    if(get_data_token(dbp,MAGIC_TOKEN,dat) == TOKEN_MISSING){
        wblprintf(LOG_WARNING,"BAYES PLUGIN", "Database is empty.\n");
        free(dat);
        return BAYES_PROB_ERR;
    }
   
    if (dat->spam_count<config->min_nspam){
        wblprintf(LOG_INFO,"BAYES PLUGIN", "Not available for scanning, only %i spam(s) in bayes DB< %i.",dat->spam_count,config->min_nspam);
        free(dat);
        return NOT_INFO_AVAILABLE;
    }
    if (dat->ham_count<config->min_nham){
        wblprintf(LOG_INFO,"BAYES PLUGIN","Not available for scanning, only %i ham(s) in bayes DB< %i",dat->ham_count,config->min_nham);
        free(dat);
        return NOT_INFO_AVAILABLE;
    }
        
    map_tokens=tokenize(mail); //Analized mail tokens
   
    linklist *list_prob=newlinkedlist();

    dbinfo *info;
    info=(dbinfo *)malloc(sizeof(dbinfo));
    info->magic_token=dat;
    info->dbp=dbp;

    hashmap_iterate_three(map_tokens, &setlistprob, info, list_prob);
    //printf("TAMAÑo LISTA: %d\n",getlengthlist(list_prob));
    
    if ((getlengthlist(list_prob)==0) ||
       ((config->require_significant_tokens>0) && (getlengthlist(list_prob)<=config->require_significant_tokens))){
        wblprintf(LOG_CRITICAL,"BAYES PLUGIN","Cannot use bayes on this message; not enough usable tokens found\n");
        free(dat);
        free(info);
        freelist(list_prob,&free_node);
        free_tokenize(map_tokens);
        return NOT_INFO_AVAILABLE;
    }
    else{
        long double result;
        result = (combine_by(list_prob,info->magic_token->spam_count, info->magic_token->ham_count));
        free(dat);
        free(info);
        freelist(list_prob,&free_node);
        free_tokenize(map_tokens);
        return result;
     }
}

int free_node(element p){
    probability *prob=(probability *)p;
    free(prob);
    return MAP_OK;
}

int setlistprob(any_t list_prob, any_t info, any_t token){
    if (strcmp((char *)token,MAGIC_TOKEN)){
        probability *p;
        //printf("ANTEsetlisS DEL MALLOC TOKEN:%s\n",(char *)token);
        if ((p = (probability *) malloc(sizeof(probability)))) {
            p->token=(char *)token;
            //printf("TOKEN:%s\n",(char *)token);
            p->prob=prob_token(token,info);
            //printf("PROBABILIDAD: %f\n",p->prob);
            if (p->prob!=NOT_INFO_AVAILABLE){
                p->prob=fabs(p->prob-0.5);
                if (p->prob >= MIN_PROB_STRENGTH)
                    //printf("PROBABILIDAD %f \n",p->prob);
                    //printf("MACRO %Lf \n",MIN_PROB_STRENGTH);
                    //printf("RESULTADO %i\n",p->prob >= MIN_PROB_STRENGTH);
                    addorder((linklist *)list_prob,p,&compare);
                else free(p);
            }else free(p);
        return MAP_OK;
        }
        //printf("Map Missing");
        return MAP_MISSING;
    }
    return MAP_OK;
}

int compare (element a, element b){
    if (((probability *)a)->prob < ((probability *)b)->prob)
        return -1;
    else 
        if (((probability *)a)->prob > ((probability *)b)->prob)
            return 1;
        else return 0;
}

void free_cache_data(element item){
    free(item);
}

int free_bayes_cache(element elem){
    c_element cache_element=(c_element)elem;
    free(cache_element->data);
    free(cache_element->key);
    free(cache_element);
    return NODE_OK;
}