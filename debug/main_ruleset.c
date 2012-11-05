/* 
 * File:   main_ruleset.c
 * Author: drordas
 *
 * Created on 12 de marzo de 2012, 17:20
 */

#include <stdio.h>
#include <stdlib.h>
#include "ruleset.h"
#include "schedule.h"
#include <time.h>

/*
 * 
 */
int main(int argc, char** argv) {
    filelist *site_config_path_fl=list_files("wb4spam_filter/","cf");
    int i;
    ruleset *rules=load_ruleset(site_config_path_fl,SPAM_FILTER);
    
    char **plugin_vector=malloc(sizeof(char *)*4);
    plugin_vector[0]="es.uvigo.es.bayes_plugin";
    plugin_vector[1]="es.uvigo.es.regex_plugin";
    plugin_vector[2]="es.uvigo.es.pcre_regex_plugin";
    plugin_vector[3]="es.uvigo.es.spf_plugin";
    
    for(i=0;i<rules->size;i++){
        if(get_rule_characteristic(rules,i) & NORMAL_RULE){
            set_definition_plugin(rules,i,plugin_vector[rand()%4]);
        }
    }
    
    _print_rules(rules);

    //printf("Before sort....\n");
/*
    for(i=0;i<count_rules(rules);i++){
        int *pos;
        if(hashmap_get(rules->map,get_rulename(rules,i),(any_t *)&pos)==MAP_MISSING &&
           hashmap_get(rules->meta_map,get_rulename(rules,i),(any_t *)&pos)==MAP_MISSING)
            printf("NO ESTA: '%s'\n",get_rulename(rules,i));
        else printf("  [%d] - '%s' -> [%d]\n",i,get_rulename(rules,i),*pos);
    }
*/
    
    //printf("................................................\n");
    
    //printf("Sorting rules....\n");
    //improved_prescheduling(rules);
    //prescheduling(rules);
    void *data;
    //plugin_separation(data, rules);
    //prescheduling(rules);
    greater_abs_value(data,rules);
    //intelligent_balance(data,rules);
    //greater_distance_value(data,rules);
    //default_plan(rules);
    //
    
    //printf("After sort....\n");
    _print_rules(rules);
    //printf("................................................\n");
    
    //default_plan(rules);

    printf("Freeying ruleset...\n");
    ruleset_free(rules);
    free(plugin_vector);
    printf("Freeying filelist...\n");
    free_filelist(site_config_path_fl);
    //out_ruleset(rules);
}


