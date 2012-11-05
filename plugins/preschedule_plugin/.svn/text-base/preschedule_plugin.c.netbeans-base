/***************************************************************************
*
*   File    : preschedule_plugin.c
*   Purpose :
*
*
*   Author  : David Ruano Ordás
*   Date    : Dacember  21, 2011
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
#include <cpluff.h>
#include <math.h>
#include "core.h"
#include "ruleset.h"
#include "vector.h"
#include "stack.h"

typedef int (*PCompareF)(void *rule1,void *rule2, void *data);

static void positive_first(void *_data, void *_rules);
static void negative_first(void *_data, void *_rules);
static void default_scheduling(void *_data, void *_rules);
static void plugin_separation(void *_data, void *_rules);
static void greater_abs_value(void *_data, void *_rules);
static void greater_distance_value(void *_data, void *_rules);
static void intelligent_balance(void *_data, void *_rules);


//PRIVATE FUNCTIONS
void ruleset_bubblesort(ruleset *_rules, PCompareF f, void *data);
int compare_rules_by_plugin(void *r1, void *r2, void *nullpointer);
int compare_rules_by_positive_score(void *r1, void *r2, void *nullpointer);
int compare_rules_by_negative_score(void *r1, void *r2, void *nullpointer);
int compare_rules_by_abs_score(void *r1, void *r2, void *nullpointer);
int compare_rules_by_greater_distance(void *r1, void *r2, void *nullpointer);
void improved_presort(ruleset *_rules);
void prescheduling(ruleset *_rules);
void move_rules(ruleset *_rules,int src,int dst);
int free_vector_element(element data);
int free_plugins(any_t item, any_t data);
void add_rule(ruleset *rules,rule *rule, int pos);

void print_rules(ruleset *_rules);
void swap_rules(ruleset *rules, int posA,int posB);
int sort_plugins(any_t item2, any_t item, any_t data);

struct schedule_data{
  prescheduler_t *funcs[7];
  cp_context_t *ctx;
};

typedef struct schedule_data schedule_data;

static void *create(cp_context_t *ctx){//Abrir bd
    schedule_data *data;
    data=(schedule_data *)malloc(sizeof(schedule_data));
    data->ctx=ctx;
    
    //START
    
    data->funcs[0]=(prescheduler_t *)malloc(sizeof(prescheduler_t));
    data->funcs[0]->function=&default_scheduling;
    data->funcs[0]->data=data;
    
    data->funcs[1]=(prescheduler_t *)malloc(sizeof(prescheduler_t));
    data->funcs[1]->function=&positive_first;
    data->funcs[1]->data=data;

    data->funcs[2]=(prescheduler_t *)malloc(sizeof(prescheduler_t));
    data->funcs[2]->function=&negative_first;
    data->funcs[2]->data=data;
    
    data->funcs[3]=(prescheduler_t *)malloc(sizeof(prescheduler_t));
    data->funcs[3]->function=&greater_abs_value;
    data->funcs[3]->data=data;
    
    data->funcs[4]=(prescheduler_t *)malloc(sizeof(prescheduler_t));
    data->funcs[4]->function=&greater_distance_value;
    data->funcs[4]->data=data;
    
    data->funcs[5]=(prescheduler_t *)malloc(sizeof(prescheduler_t));
    data->funcs[5]->function=&intelligent_balance;
    data->funcs[5]->data=data;
    
    data->funcs[6]=(prescheduler_t *)malloc(sizeof(prescheduler_t));
    data->funcs[6]->function=&plugin_separation;
    data->funcs[6]->data=data;
        
    return data;
}

static int start(void *d){//LLamo a la funcion
    schedule_data *data=(schedule_data *)d;
    
    //Dinamyc plugin initialization
    if (cp_define_symbol(data->ctx, "es_uvigo_ei_default_scheduling", data->funcs[0])==CP_OK &&
        cp_define_symbol(data->ctx, "es_uvigo_ei_positive_first", data->funcs[1])==CP_OK &&
        cp_define_symbol(data->ctx, "es_uvigo_ei_negative_first", data->funcs[2])==CP_OK &&
        cp_define_symbol(data->ctx, "es_uvigo_ei_greater_abs_value", data->funcs[3])==CP_OK &&
        cp_define_symbol(data->ctx, "es_uvigo_ei_greater_distance_value", data->funcs[4])==CP_OK &&
        cp_define_symbol(data->ctx, "es_uvigo_ei_intelligent_balance", data->funcs[5])==CP_OK &&
        cp_define_symbol(data->ctx, "es_uvigo_ei_plugin_separation", data->funcs[6])==CP_OK)
       return CP_OK;
    else return CP_ERR_RESOURCE;
}

static void stop(void *d) {
     //VOID
     
}

static void destroy(void *d) {
    schedule_data *data=(schedule_data *)d;
    
    free(data->funcs[0]);
    free(data->funcs[1]);
    free(data->funcs[2]);
    free(data->funcs[3]);
    free(data->funcs[4]);
    free(data->funcs[5]);
    free(data->funcs[6]);
    free(data);
}

void plugin_separation(void *_data, void *_rules){
   wblprintf(LOG_INFO,"PRESCHEDULING","Running plugin_separation\n"); 
   ruleset *r=(ruleset *)_rules;  
   prescheduling(r);
   
   
   //ruleset_bubblesort(r,&compare_rules_by_plugin,NULL);
   int i=0;
   stack *plugin_index; 
   
   map_t plugins=hashmap_new();
   
   for(i=r->sdata_t->begin_normal;i<r->size;i++){ 
       if(r->rules[i].characteristic & NORMAL_RULE){
           if (hashmap_get(plugins,((definition *)r->rules[i].def)->plugin,
                                    (any_t *)&plugin_index)==MAP_MISSING){
               plugin_index=newstack();
           }
           rule *aux=malloc(sizeof(rule));
           memcpy(aux,&(r->rules[i]),sizeof(rule));
           push_item((stack *)plugin_index,aux);
           
           hashmap_put(plugins,((definition *)r->rules[i].def)->plugin,plugin_index);
       }
   }
   
   int *ptr=malloc(sizeof(int));
   *ptr=i=r->sdata_t->begin_normal;
   //printf("1-*ptr=%d\n",i);
   while(*ptr<r->size){ 
       hashmap_iterate_items(plugins,&sort_plugins,r,ptr);
       //printf("2-*ptr=%d\n",*ptr);
   }
   free(ptr);
   hashmap_iterate(plugins,&free_plugins,NULL);
   hashmap_free(plugins);
   
   //print_rules(r);
   
}

int sort_plugins(any_t item2, any_t item, any_t data){
    stack *aux=(stack *)data;
    ruleset *r=(ruleset *)item;
    int *i=((int *)item2);
    //printf("1.1-*ptr=%d\n",*i);
    
    rule *_rule;
    
    if(aux!=NULL && getlengthstack(aux)>0 && pop_item(aux,(any_t *)&_rule)==ELEMENT_FOUND){
       //printf("RULE...%s\n",_rule->rulename);
       //printf("[%d] %s-%s\n",*i,_rule->rulename,((definition *)_rule->def)->plugin);
       add_rule(r,_rule,*i);
       free(_rule);
       (*i)++;
    }
    
    //printf("1.2-*ptr=%d\n",*i);
    return MAP_OK;
}

int free_plugins(any_t item, any_t data){
    (data!=NULL)?(free(data)):(0);
    return MAP_OK;
}

static void default_scheduling(void *_data, void *_rules){
   //schedule_data *data =(schedule_data *)_data;
   //printf("INITIALIZING DEFAULT_PRESCHEDULING\n");
    
   wblprintf(LOG_INFO,"PRESCHEDULING","Running default_scheduling\n"); 
  
   
   //int i,j,k,numplugins;
   //rule *tmp;
   //map_t plugins;
   //char *s;
   ruleset *r=(ruleset *)_rules;  
   
   prescheduling(r);
   
/*
   printf("PRESCHEDULING................\n");
   print_rules(r);
   printf(".............................\n");
   
   plugins=hashmap_new();
   
   for(i=r->sdata_t->begin_normal ;i<r->size;i++){
        if (hashmap_get(plugins,((definition *)r->rules[i].def)->plugin,
                                 (any_t *)&s)!=MAP_MISSING)
            hashmap_put(plugins,((definition *)r->rules[i].def)->plugin,
                                ((definition *)r->rules[i].def)->plugin);
   }
   
   numplugins=hashmap_length(plugins);
   hashmap_free(plugins);
   printf("begin normal %d\n",r->sdata_t->begin_normal);
   tmp=malloc(sizeof(rule));
   
   
   qsort(r->rules[r->sdata_t->begin_normal], r->size, sizeof(rule), &compare_rules_by_plugin);	

   //schedule the plugins
   for(k=1;k<numplugins;k++){
      for(i=k;i<r->size;i++){
      	  for(j=1;j<r->size/k && !strcmp(((definition *)r->rules[(i+k)%r->size].def)->plugin,((definition *)r->rules[(i+k*j)%r->size].def)->plugin);j++);
      	  if (j<r->size/k){
             memcpy(tmp,&(r->rules[(i+k)%r->size]),sizeof(rule));
             memcpy(&(r->rules[(i+k)%r->size]),&(r->rules[(i+j*k)%r->size]),sizeof(rule));
             memcpy(&(r->rules[(i+j*k)%r->size]),tmp,sizeof(rule));
          }
     }
   }
   free(tmp);
   
   printf("DEFAULT_SCHEDULING................\n");
   print_rules(r);
   printf(".............................\n");
   
   exit(EXIT_SUCCESS);
*/
   
}

static void positive_first(void *_data, void *_rules){
    ruleset *r=(ruleset *)_rules;
    
    wblprintf(LOG_INFO,"PRESCHEDULING","Running 'positive_first' scheduling\n");  
    
    prescheduling(r);
/*
    printf("------AFTER PRESCHEDULING------\n");
    _print_rules(r);
    printf("-------------------------------\n");
*/
    
    ruleset_bubblesort(r,&compare_rules_by_positive_score,NULL);
    
/*
    printf("------AFTER POSITIVE_FIRST------\n");
    _print_rules(r);
    printf("--------------------------------\n");
*/
    
}

static void negative_first(void *_data, void *_rules){
    ruleset *r=(ruleset *)_rules;
    
    wblprintf(LOG_INFO,"PRESCHEDULING","Running 'negative_first' scheduling\n");  
    
    prescheduling(r);
    
/*
    printf("------AFTER PRESCHEDULING------\n");
    _print_rules(r);
    printf("-------------------------------\n");
*/
    
    ruleset_bubblesort(r,&compare_rules_by_negative_score,NULL);
    
/*
    printf("------AFTER POSITIVE_FIRST------\n");
    _print_rules(r);
    printf("--------------------------------\n");    
*/
}

static void greater_abs_value(void *_data, void *_rules){
    ruleset *r=(ruleset *)_rules;
    wblprintf(LOG_INFO,"PRESCHEDULING","Running 'greater_abs_value_first' scheduling\n");  
    
    prescheduling(r);

/*
    printf("------AFTER PRESCHEDULING------\n");
    _print_rules(r);
    printf("-------------------------------\n");
*/
    
    ruleset_bubblesort(r,&compare_rules_by_abs_score,NULL);

/*
    printf("------AFTER POSITIVE_FIRST------\n");
    _print_rules(r);
    printf("--------------------------------\n");    
*/
    
}

static void greater_distance_value(void *_data, void *_rules){
    ruleset *r=(ruleset *)_rules;
    wblprintf(LOG_INFO,"PRESCHEDULING","Running 'greater_distance_value_first' scheduling\n");  
    
    prescheduling(r);
    
/*
    printf("------AFTER PRESCHEDULING------\n");
    _print_rules(r);
    printf("-------------------------------\n");
*/
    
    ruleset_bubblesort(r,&compare_rules_by_greater_distance,&(r->required));
    
/*
    printf("------AFTER POSITIVE_FIRST------\n");
    _print_rules(r);
    printf("--------------------------------\n");    
*/
}

void intelligent_balance(void *_data, void *_rules){
    ruleset *r=(ruleset *)_rules;
    
    wblprintf(LOG_INFO,"PRESCHEDULING","Running 'intelligent_balance' scheduling\n");  
    
    int n=count_rules(r);
    int i=0;
    int num_positive=0;
    int num_negative=0;
    
    prescheduling(r);
    
/*
    printf("------AFTER PRESCHEDULING------\n");
    _print_rules(r);
    printf("-------------------------------\n");
*/
       
    for(i=r->sdata_t->begin_normal;i<n;i++){ 
        if( r->rules[i].characteristic & NORMAL_SCORE &&
            !is_dependant_rule(r,i))
        {
                (*(float *)(r->rules[i].score)>=0)?
                    (num_positive++):
                    (num_negative++);
        }
    }
    
    ruleset *pos_rules=malloc(sizeof(ruleset));
    pos_rules->rules=(rule *)malloc(sizeof(rule)*(num_positive));
    pos_rules->size=num_positive;
    pos_rules->dependant_map=r->dependant_map;
    pos_rules->meta_map=r->meta_map;
    pos_rules->map=r->map;
    //pos_rules->sdata_t->definitive_size=0;
    
    ruleset *neg_rules=malloc(sizeof(ruleset));
    neg_rules->rules=(rule *)malloc(sizeof(rule)*(num_negative));
    neg_rules->size=num_negative;
    neg_rules->dependant_map=r->dependant_map;
    neg_rules->meta_map=r->meta_map;
    neg_rules->map=r->map;
    //neg_rules->sdata_t->definitive_size=0;
    
    int count_pos=0;
    int count_neg=0;
    
    for(i=r->sdata_t->begin_normal;i<n;i++)
        if(get_rule_characteristic(r,i) & NORMAL_RULE &&
           get_rule_characteristic(r,i) & NORMAL_SCORE &&
           !is_dependant_rule(r,i)){
            (*(float *)(r->rules[i].score)>=0)?
                (memcpy(&(pos_rules->rules[count_pos++]),&(r->rules[i]),sizeof(r->rules[i]))):
                (memcpy(&(neg_rules->rules[count_neg++]),&(r->rules[i]),sizeof(r->rules[i])));
        }

    
    if ((num_positive+num_negative)>(n)){
        wblprintf(LOG_CRITICAL,"PRESCHEDULE PLUGIN","Prescheduling method failed. Rules not scheduled using intelligent balance method\n");
        free(pos_rules->rules);
        free(pos_rules);
        
        free(neg_rules->rules);
        free(neg_rules);
        return ;
        
    }
    
    ruleset_bubblesort(pos_rules,&compare_rules_by_positive_score,NULL);
    
    ruleset_bubblesort(neg_rules,&compare_rules_by_negative_score,NULL);   
    
    int count=r->sdata_t->begin_normal;
    int *rulepos;
    if(fabs(r->intervals->positive)>=fabs(r->intervals->negative)){
        for (i=0;i<num_positive;i++){
            memcpy(&(r->rules[count]),&(pos_rules->rules[i]),sizeof(pos_rules->rules[i]));
            hashmap_get(r->map,get_rulename(r,count),(any_t *)&rulepos);
            *rulepos=count++;
        }
        for (i=0;i<num_negative;i++){    
            memcpy(&(r->rules[count]),&(neg_rules->rules[i]),sizeof(neg_rules->rules[i]));
            hashmap_get(r->map,get_rulename(r,count),(any_t *)&rulepos);
            *rulepos=count++;
        }
    }
    else{
        for (i=0;i<num_negative;i++){    
            memcpy(&(r->rules[count]),&(neg_rules->rules[i]),sizeof(neg_rules->rules[i]));
            hashmap_get(r->map,get_rulename(r,count),(any_t *)&rulepos);
            *rulepos=count++;
        }
        for (i=0;i<num_positive;i++){
            memcpy(&(r->rules[count]),&(pos_rules->rules[i]),sizeof(pos_rules->rules[i]));
            hashmap_get(r->map,get_rulename(r,count),(any_t *)&rulepos);
            *rulepos=count++;
        }
    }
    
    free(pos_rules->rules);
    free(pos_rules);
    
    free(neg_rules->rules);
    free(neg_rules);
    
    //printf("------AFTER POSITIVE_FIRST------\n");
    //print_rules(r);
    //printf("--------------------------------\n");    
    //print_rules(r);
}

//PRIVATE FUNCTIONS

void prescheduling(ruleset *_rules){//, PSortF f){
    int i,j;
    map_t ins_dep=hashmap_new();
    map_t processed_meta=hashmap_new();
    int global_dependant_meta=0;
    short has_meta_dependant=0;
    
    improved_presort(_rules);
    
    int count_meta=0;
    do{
        for(i=0;i<count_rules(_rules);i++){
            int *main_meta;
            if( (get_rule_characteristic(_rules,i) & META_RULE) &&
                (hashmap_get(processed_meta,get_rulename(_rules,i),
                             (any_t *)&main_meta)==MAP_MISSING))
            {
               hashmap_get(_rules->meta_map,get_rulename(_rules,i),(any_t *)&main_meta); 
               count_meta++;
               if(is_valid_meta(_rules,i)){ 
                   vector *dep=get_dependant_rules(_rules,i);
                   int *pos;
                   hashmap_get(_rules->meta_map,get_rulename(_rules,i),(any_t *)&pos);
                   hashmap_put(processed_meta,get_rulename(_rules,i),(any_t)pos);
                   for(j=0;j<dep->size;j++){
                       int *res;
                       if(hashmap_get(ins_dep,((char *)dep->v[j]),(any_t *)&res)==MAP_MISSING){
                           int *rulepos;                       
                           if(hashmap_get(_rules->map,((char *)dep->v[j]),(any_t *)&rulepos)!=MAP_MISSING){
                               if(*rulepos > *main_meta){
                                   move_rules(_rules,*main_meta,*rulepos);
                                   hashmap_put(ins_dep,((char *)dep->v[j]),main_meta);
                               }
                           }else{
                               if(hashmap_get( _rules->meta_map,((char *)dep->v[j]),
                                               (any_t *)&rulepos)!=MAP_MISSING)
                                  has_meta_dependant=1; 
                           }
                       }
                   }
               } 
               else{ 
                   wblprintf(LOG_WARNING,"PRESCHEDULING","META '%s' is composed by non-existent rules. Aborting rule execution\n",get_rulename(_rules,i));
                   free(_rules->rules[i].score);
                   float *new_score = malloc(sizeof(float));
                   *new_score=0;
                   _rules->rules[i].score=new_score;
                   _rules->rules[i].characteristic = META_RULE;
                   _rules->rules[i].characteristic |= NORMAL_SCORE;
               }
               _rules->sdata_t->end_meta=(*main_meta);
               if(count_meta>=count_meta_rules(_rules)) break;
            }else{
                if(get_rule_characteristic(_rules,i) & DEFINITIVE_SCORE){
                    _rules->sdata_t->end_definitive=i;
                }
            }
        }
        global_dependant_meta=(has_meta_dependant==1);
    }while(global_dependant_meta);
    
    hashmap_free(ins_dep);
    hashmap_free(processed_meta);
    
    (_rules->sdata_t->end_definitive >= _rules->sdata_t->end_meta)?
        (_rules->sdata_t->begin_normal=_rules->sdata_t->end_definitive+1):
        (_rules->sdata_t->begin_normal=_rules->sdata_t->end_meta+1);
    //printf("END META '%s'-[%d]\n",get_rulename(_rules,_rules->sdata_t->end_meta),_rules->sdata_t->end_meta);
    //printf("END DEFINITIVE '%s'-[%d]\n",get_rulename(_rules,_rules->sdata_t->end_definitive),_rules->sdata_t->end_definitive);
    //printf("BEGIN NORMAL '%s'-[%d]\n",get_rulename(_rules,_rules->sdata_t->begin_normal),_rules->sdata_t->begin_normal);
    
}


void improved_presort(ruleset *_rules){
    int i=0;
    int begin_def=0;
    int begin_meta=count_definitive_rules(_rules);
    
    for(;i<count_rules(_rules);i++){
        if( get_rule_characteristic(_rules,i) & DEFINITIVE_SCORE ) {
            for(begin_def=0;(get_rule_characteristic(_rules,begin_def) & DEFINITIVE_SCORE) ||
                 (get_rule_characteristic(_rules,begin_def) & NORMAL_SCORE &&
                  get_rule_characteristic(_rules,begin_def) & META_RULE &&
                 (begin_def<=count_definitive_rules(_rules)));begin_def++);
            swap_rules(_rules,i,begin_def);
        }
        else{ 
            if( get_rule_characteristic(_rules,i) & META_RULE) {
                for(begin_meta=count_definitive_rules(_rules);( get_rule_characteristic(_rules,begin_meta) & DEFINITIVE_SCORE ) ||
                    (get_rule_characteristic(_rules,begin_meta) & NORMAL_SCORE &&
                     get_rule_characteristic(_rules,begin_meta) & META_RULE &&
                     ((begin_meta-count_definitive_rules(_rules)))<=count_definitive_rules(_rules));begin_meta++);
                swap_rules(_rules,i,begin_meta);
            }
        }
    } 
}

void move_rules(ruleset *_rules,int src,int dst){
    int i;
    int *posA;
    
    if(dst-src==1) swap_rules(_rules,src,dst);
    else{
        rule *aux=malloc(sizeof(rule));
        memcpy(aux,&(_rules->rules[dst]),sizeof(rule));
        for(i=dst-1;i>=src;i--){
            memcpy(&(_rules->rules[i+1]),&(_rules->rules[i]),sizeof(rule));
            if(hashmap_get(_rules->map,get_rulename(_rules,i+1),(any_t *)&posA)==MAP_MISSING &&
               hashmap_get(_rules->meta_map,get_rulename(_rules,i+1),(any_t *)&posA)==MAP_MISSING){
                wblprintf(LOG_CRITICAL,"PRESCHEDULE","Rule '%s' does not exist. Aborting..\n",get_rulename(_rules,i));
                exit(EXIT_FAILURE);
            }
            *posA=(i+1);
        }
        memcpy(&(_rules->rules[src]),aux,sizeof(rule));
        if(hashmap_get(_rules->map,get_rulename(_rules,src),(any_t *)&posA)==MAP_MISSING &&
           hashmap_get(_rules->meta_map,get_rulename(_rules,src),(any_t *)&posA)==MAP_MISSING){
           wblprintf(LOG_CRITICAL,"PRESCHEDULE","Rule '%s' does not exist. Aborting..\n",get_rulename(_rules,i));
           exit(EXIT_FAILURE);
        }
            
        *posA=src;
        free(aux);
    }
} 
void add_rule(ruleset *rules,rule *aux, int pos){
    int *p1;
    
/*
    printf("RULE SORT [%d]\n",pos);
    printf(" NAME :%s\n",aux->rulename);
    printf(" SCORE :%2.2f\n",*(float *)aux->score);
    printf(" PLUGIN :%s\n",((definition *)aux->def)->plugin);
*/
    
    memcpy( &(rules->rules[pos]),aux,sizeof(rule));
    
    if( hashmap_get(rules->map,aux->rulename,(any_t *)&p1)==MAP_MISSING &&
        hashmap_get(rules->meta_map,aux->rulename,(any_t *)&p1)==MAP_MISSING )
    {
        wblprintf(LOG_CRITICAL,"PRESCHEDULE","Rule '%s' or '%s' does not exist. Aborting..\n",get_rulename(rules,pos));
        exit(EXIT_FAILURE);    
    }
    
    
/*
    printf("ADD_RULE [%d]\n",pos);
    printf(" NAME :%s\n",rules->rules[pos].rulename);
    printf(" SCORE :%2.2f\n",*(float *)rules->rules[pos].score);
    printf(" PLUGIN :%s\n",((definition *)rules->rules[pos].def)->plugin);
*/
    *p1=pos; 
    
}

void swap_rules(ruleset *rules, int posA,int posB){
    rule *temp=(rule *)malloc(sizeof(rule));
    int *p1, *p2;
    
    memcpy(temp,&(rules->rules[posA]),sizeof(rule));
    memcpy(&(rules->rules[posA]),&(rules->rules[posB]),sizeof(rule));
    memcpy(&(rules->rules[posB]),temp,sizeof(rule));
    
    free(temp);
    
    if( ( hashmap_get(rules->map,get_rulename(rules,posA),(any_t *)&p1)==MAP_MISSING &&
          hashmap_get(rules->meta_map,get_rulename(rules,posA),(any_t *)&p1)==MAP_MISSING ) 
        ||
        ( hashmap_get(rules->map,get_rulename(rules,posB),(any_t *)&p2)==MAP_MISSING &&
          hashmap_get(rules->meta_map,get_rulename(rules,posB),(any_t *)&p2)==MAP_MISSING ) ){
          wblprintf(LOG_CRITICAL,"PRESCHEDULE","Rule '%s' or '%s' does not exist. Aborting..\n",get_rulename(rules,posA),get_rulename(rules,posB));
          exit(EXIT_FAILURE);    
    }
    *p1=posA;
    *p2=posB;
}

void ruleset_bubblesort(ruleset *_rules, PCompareF f, void *data){
    ruleset *r=(ruleset *)_rules;
    int i=0;//=count_definitive_rules(r);
    int j=0;//=count_definitive_rules(r);
    int k=0;
    
    int n=count_rules(r);
    int *rulepos;
    for(i=0;i<(n-1);i++){
        for(j=0;j<(n-(i+1));j++){
            if(get_rule_characteristic(r,j) & NORMAL_RULE &&
               get_rule_characteristic(r,j) & NORMAL_SCORE &&
               hashmap_get(r->dependant_map,get_rulename(r,j),(any_t *)&rulepos)==MAP_MISSING)
            {
               for(k=j+1;k<count_rules(r) && 
                    ( get_rule_characteristic(r,k) & DEFINITIVE_SCORE ||
                      get_rule_characteristic(r,k) & META_RULE  ||
                      hashmap_get(r->dependant_map,get_rulename(r,k),(any_t* )&rulepos)!=MAP_MISSING);k++);
               if(f(&(r->rules[j]),&(r->rules[k]),data)==1){
                    swap_rules(_rules,j,k);
               }
            }
        }
    }    
}

void print_rules(ruleset *_rules){
    int i;
    for(i=0;i<count_rules(_rules);i++){
        int *pos;
        if(hashmap_get(_rules->map,get_rulename(_rules,i),(any_t *)&pos)==MAP_MISSING &&
           hashmap_get(_rules->meta_map,get_rulename(_rules,i),(any_t *)&pos)==MAP_MISSING)
            printf("NO ESTA: '%s'\n",get_rulename(_rules,i));
        else{ 
            (get_rule_characteristic(_rules,i) & DEFINITIVE_SCORE)?
               (printf("  [%d] - '%s' -> [%d] (%s)",i,get_rulename(_rules,i),*pos,(char *)get_rule_score(_rules,i))):
               (printf("  [%d] - '%s' -> [%d] (%2.2f)",i,get_rulename(_rules,i),*pos,*(float *)get_rule_score(_rules,i)));
            (get_rule_characteristic(_rules,i) & META_RULE)?
               (printf(" |null|\n")):
               (printf(" |%s|\n",((definition *)_rules->rules[i].def)->plugin));
        }
    }
}

int compare_rules_by_positive_score(void *r1, void *r2, void *nullpointer){
    rule *rule1 = (rule *)r1;
    rule *rule2 = (rule *)r2;

    if( (rule1->characteristic & NORMAL_SCORE) && 
        (rule2->characteristic & NORMAL_SCORE) )
        return(*(float *)rule1->score<*(float *)rule2->score);
    else return 0;
   
}

int compare_rules_by_negative_score(void *r1, void *r2, void *nullpointer){
    rule *rule1 = (rule *)r1;
    rule *rule2 = (rule *)r2;

    if( (rule1->characteristic & NORMAL_SCORE) && 
        (rule2->characteristic & NORMAL_SCORE) )
        return (*(float *)rule1->score>*(float *)rule2->score);
    else return 0;
}

int compare_rules_by_abs_score(void *r1, void *r2, void *nullpointer){
    rule *rule1 = (rule *)r1;
    rule *rule2 = (rule *)r2;
    
    if( (rule1->characteristic & NORMAL_SCORE) && 
        (rule2->characteristic & NORMAL_SCORE) )
        return (fabs(*(float *)rule1->score)<fabs(*(float *)rule2->score));
    else return 0;
}

int compare_rules_by_greater_distance(void *r1, void *r2, void *required_score){
    rule *rule1 = (rule *)r1;
    rule *rule2 = (rule *)r2;
    float score = *((float *)required_score);
    
    if( (rule1->characteristic & NORMAL_SCORE) && 
        (rule2->characteristic & NORMAL_SCORE) )
        return (fabs(*(float *)rule1->score-score)<fabs(*(float *)rule2->score-score));
    else return 0;
}

int compare_rules_by_plugin(void *r1, void *r2, void *nullpointer){
    rule *rule1 = (rule *)r1;
    rule *rule2 = (rule *)r2;
    
    if( (rule1->characteristic & NORMAL_RULE) && 
        (rule2->characteristic & NORMAL_RULE) )
        return (strcmp(((definition *)rule1->def)->plugin,((definition *)rule2->def)->plugin)==0);
    else return 0;
}

int free_vector_element(element data){
    free((char *)data);
    return VECTOR_OK;
}

CP_EXPORT cp_plugin_runtime_t preschedule_plugin_runtime_functions = {create, start, stop, destroy};