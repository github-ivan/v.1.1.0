/* 
 * File:   schedule.c
 * Author: drordas
 *
 * Created on 13 de octubre de 2011, 12:28
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>

#include "ruleset.h"
#include "schedule.h"
#include "meta.h"
#include "stack.h"
#include "hashmap.h"

typedef int (*PCompareF)(void *rule1,void *rule2, void *data);

int sort_plugins(any_t item2, any_t item, any_t data);
int compare_rules_by_plugin(const void *_a, const void *_b);
int compare_rules_by_positive_score(void *r1, void *r2, void *nullpointer);
void move_rules(ruleset *_rules,int src,int dst);
void preschedule_rules(ruleset *_rules);
void improved_presort(ruleset *_rules);
void swap_rules(ruleset *rules, int posA,int posB);
void ruleset_bubblesort(ruleset *_rules, PCompareF f, void *data);
void _print_rules(ruleset *_rules);
void free_invalid_meta(ruleset *_rules,int rulepos, PFree f);
int free_plugins(any_t item, any_t data);
/*
 * 
 */

typedef struct preschedule_data_t preschedule_data_t;

void default_plan(void *rules){
   int i,j,k,numplugins;
   rule *tmp;
   map_t plugins=hashmap_new();
   char *s;

   ruleset *r=(ruleset *)rules;
   
   //int begin_schedule=prescheduling(rules);
   prescheduling(rules);
   
   
/*
   printf("After sort....\n");
   _print_rules(rules);
   printf("..........DEFAULT_SCHEDULING..............\n");   
   
   for (i=r->sdata_t->begin_normal;i<r->size;i++){
       if(get_rule_characteristic(r,i) & NORMAL_RULE &&
          get_rule_characteristic(r,i) & NORMAL_SCORE &&
          !is_dependant_rule(r,i)){
           printf("[%d]-%s\n",i,get_rulename(r,i));
   	   (hashmap_get(plugins,((definition *)r->rules[i].def)->plugin,(any_t *)&s)==MAP_MISSING)?
   	       (hashmap_put(plugins,((definition *)r->rules[i].def)->plugin,((definition *)r->rules[i].def)->plugin)):
               (0);
       }
   }
   numplugins=hashmap_length(plugins);
   hashmap_free(plugins);
   
   tmp=malloc(sizeof(rule));
   
   ruleset *aux=malloc(sizeof(ruleset));
   aux->rules=(rule *)malloc(sizeof(rule)*(r->size-r->sdata_t->begin_normal));
   aux->size=(r->size-r->sdata_t->begin_normal);
   aux->dependant_map=r->dependant_map;
   aux->meta_map=r->meta_map;
   aux->map=r->map;

    //i=r->sdata_t->begin_normal
   int count_rules=0;
   for(i=r->sdata_t->begin_normal;i<r->size;i++){
       memcpy(&(aux->rules[count_rules++]),&(r->rules[i]),sizeof(r->rules[i]));
   }
   
   
   qsort(r->rules, r->size, sizeof(rule), &compare_rules_by_plugin);	

   //schedule the plugins
   for(k=1;k<numplugins;k++)
      for(i=k;i<r->size;i++){
      	  for(j=1;j<r->size/k && !strcmp(((definition *)r->rules[(i+k)%r->size].def)->plugin,((definition *)r->rules[(i+k*j)%r->size].def)->plugin);j++);
      	  if (j<r->size/k){
             memcpy(tmp,&(r->rules[(i+k)%r->size]),sizeof(rule));
             memcpy(&(r->rules[(i+k)%r->size]),&(r->rules[(i+j*k)%r->size]),sizeof(rule));
             memcpy(&(r->rules[(i+j*k)%r->size]),tmp,sizeof(rule));
          }
     }
	  
   free(tmp);
*/
}


int compare_rules_by_plugin(const void *_a, const void *_b){
    rule *a, *b;
    a=(rule *)_a;
    b=(rule *)_b;
    if( (a->characteristic & NORMAL_RULE && a->characteristic & NORMAL_SCORE) &&
        (b->characteristic & NORMAL_RULE && b->characteristic & NORMAL_SCORE) )
        return strcmp(((definition *)a->def)->plugin, ((definition *)b->def)->plugin);
    else
        return 1;
}

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

void free_invalid_meta(ruleset *_rules,int rulepos, PFree f){
    free(((meta_definition *)_rules->rules[rulepos].def)->expresion);
    ((meta_definition *)_rules->rules[rulepos].def)->expresion=NULL;
    free_vector((((meta_definition *)_rules->rules[rulepos].def)->dependant_rules),f);    
    ((meta_definition *)_rules->rules[rulepos].def)->dependant_rules=NULL;
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

void preschedule_rules(ruleset *_rules){
    int i, begin_def=0;
    int *posA;
    int *posB;
    (count_definitive_rules(_rules)==0)?
      (wblprintf(LOG_DEBUG,"PRESCHEDULING","Definitive rules not found\n")):
      (0);
    
    for(i=0;i<count_rules(_rules) && begin_def<=count_definitive_rules(_rules);i++){
        if(get_rule_characteristic(_rules,i) & DEFINITIVE_SCORE){
            rule *aux=malloc(sizeof(rule));
            memcpy(aux,&(_rules->rules[begin_def]),sizeof(rule));
            memcpy(&(_rules->rules[begin_def]),&(_rules->rules[i]),sizeof(rule));
            memcpy(&(_rules->rules[i]),aux,sizeof(rule));
            free(aux);
            if( ( hashmap_get(_rules->map,get_rulename(_rules,i),(any_t *)&posA)==MAP_MISSING &&
                  hashmap_get(_rules->meta_map,get_rulename(_rules,i),(any_t *)&posA)==MAP_MISSING ) 
                ||
                ( hashmap_get(_rules->map,get_rulename(_rules,begin_def),(any_t *)&posB)==MAP_MISSING && 
                  hashmap_get(_rules->meta_map,get_rulename(_rules,begin_def),(any_t *)&posB)==MAP_MISSING) ){
               wblprintf(LOG_CRITICAL,"PRESCHEDULE","Rule '%s' or '%s' does not exist. Aborting..\n",get_rulename(_rules,begin_def),get_rulename(_rules,i));
               exit(EXIT_FAILURE);
            }else{
                *posA=i;
                *posB=begin_def;
            }
            begin_def++==count_definitive_rules(_rules);
        }
    }
}

void improved_presort(ruleset *_rules){
    int i=0;
    int begin_def=0;
    int begin_meta=count_definitive_rules(_rules);
    
    for(;i<count_rules(_rules);i++){
        if( get_rule_characteristic(_rules,i) & DEFINITIVE_SCORE ) {
            printf("DEFINITIVA NO META %s\n",_rules->rules[i].rulename);
            for(begin_def=0;(get_rule_characteristic(_rules,begin_def) & DEFINITIVE_SCORE) ||
                 (get_rule_characteristic(_rules,begin_def) & NORMAL_SCORE &&
                  get_rule_characteristic(_rules,begin_def) & META_RULE) &&
                 (begin_def<=count_definitive_rules(_rules));begin_def++);
            swap_rules(_rules,i,begin_def);
        }
        else{ 
            if( get_rule_characteristic(_rules,i) & META_RULE) {
                for(begin_meta=count_definitive_rules(_rules);( get_rule_characteristic(_rules,begin_meta) & DEFINITIVE_SCORE ) ||
                    (get_rule_characteristic(_rules,begin_meta) & NORMAL_SCORE &&
                     get_rule_characteristic(_rules,begin_meta) & META_RULE) &&
                     ((begin_meta-count_definitive_rules(_rules))<=count_definitive_rules(_rules));begin_meta++);
                swap_rules(_rules,i,begin_meta);
            }
        }
    } 
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

void _print_rules(ruleset *_rules){
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

    if( (rule1->characteristic & NORMAL_RULE) && 
        (rule2->characteristic & NORMAL_SCORE) )
        return(*(float *)rule1->score<*(float *)rule2->score);
    else return 0;
   
}

void positive_first(void *_data, void *_rules){
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

int compare_rules_by_negative_score(void *r1, void *r2, void *nullpointer){
    rule *rule1 = (rule *)r1;
    rule *rule2 = (rule *)r2;

    if( (rule1->characteristic & NORMAL_SCORE) && 
        (rule2->characteristic & NORMAL_SCORE) )
        return (*(float *)rule1->score>*(float *)rule2->score);
    else return 0;
}

void negative_first(void *_data, void *_rules){
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

int compare_rules_by_abs_score(void *r1, void *r2, void *nullpointer){
    rule *rule1 = (rule *)r1;
    rule *rule2 = (rule *)r2;
    
    if( (rule1->characteristic & NORMAL_SCORE) && 
        (rule2->characteristic & NORMAL_SCORE) )
        return (fabs(*(float *)rule1->score)<fabs(*(float *)rule2->score));
    else return 0;
}

void greater_abs_value(void *_data, void *_rules){
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

int compare_rules_by_greater_distance(void *r1, void *r2, void *required_score){
    rule *rule1 = (rule *)r1;
    rule *rule2 = (rule *)r2;
    float score = *((float *)required_score);
    
    if( (rule1->characteristic & NORMAL_SCORE) && 
        (rule2->characteristic & NORMAL_SCORE) )
        return (fabs(*(float *)rule1->score-score)<fabs(*(float *)rule2->score-score));
    else return 0;
}


void greater_distance_value(void *_data, void *_rules){
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
       
    for(i=r->sdata_t->begin_normal;i<n;i++){ 
        if( get_rule_characteristic(r,i) & NORMAL_SCORE &&
            get_rule_characteristic(r,i) & NORMAL_RULE &&
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
    //i=r->sdata_t->begin_normal
    for(i=r->sdata_t->begin_normal;i<n;i++){
        if(get_rule_characteristic(r,i) & NORMAL_RULE &&
           get_rule_characteristic(r,i) & NORMAL_SCORE &&
           !is_dependant_rule(r,i)){
            (*(float *)(r->rules[i].score)>=0)?
                (memcpy(&(pos_rules->rules[count_pos++]),&(r->rules[i]),sizeof(r->rules[i]))):
                (memcpy(&(neg_rules->rules[count_neg++]),&(r->rules[i]),sizeof(r->rules[i])));
        }
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
    
    //int count=r->sdata_t->begin_normal;
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
    
/*
    printf("------AFTER POSITIVE_FIRST------\n");
    _print_rules(r);
    printf("--------------------------------\n");    
*/
    
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

void add_rule(ruleset *rules,rule *aux, int pos){
    int *p1;
    
    memcpy( &(rules->rules[pos]),aux,sizeof(rule));
    
    if( hashmap_get(rules->map,aux->rulename,(any_t *)&p1)==MAP_MISSING &&
        hashmap_get(rules->meta_map,aux->rulename,(any_t *)&p1)==MAP_MISSING )
    {
        wblprintf(LOG_CRITICAL,"PRESCHEDULE","Rule '%s' or '%s' does not exist. Aborting..\n",get_rulename(rules,pos));
        exit(EXIT_FAILURE);    
    }
    *p1=pos; 
    
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
           hashmap_put(plugins,((definition *)aux->def)->plugin,plugin_index);
       }
   }
   
   int *ptr=malloc(sizeof(int));
   *ptr=r->sdata_t->begin_normal;
   //printf("1-*ptr=%d\n",i);
   while(*ptr<r->size){ 
       hashmap_iterate_items(plugins,&sort_plugins,r,ptr);
       //printf("2-*ptr=%d\n",*ptr);
   }
   free(ptr);
   hashmap_iterate(plugins,&free_plugins,NULL);
   hashmap_free(plugins);
   
}

int sort_plugins(any_t item2, any_t item, any_t data){
    stack *aux=(stack *)data;
    ruleset *r=(ruleset *)item;
    int *i=((int *)item2);
    //printf("1.1-*ptr=%d\n",*i);
    
    rule *_rule;
    
    if(aux!=NULL && getlengthstack(aux)>0 && pop_item(aux,(any_t *)&_rule)==ELEMENT_FOUND){
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