/***************************************************************************
*
*   File    : eml_parser.c
*   Purpose : Implements a parser of HTML part contents
*
*   Author: Jose Ramon Mendez
*
*
*   Date    : March  07, 2011
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

#include "html.h"
#include "logger.h"
#include "hashmap.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>
#include "string_util.h"

/**The HTML dumper */
HTMLdumper *HTMLd=NULL;

/**
  * HTMLEntity2ascii table
  * made from http://www.w3schools.com/tags/ref_entities.asp
  * and http://www.elcodigoascii.com.ar/codigo-ascii.php
  */
const char *html_entities[256]={
	NULL, //0
	NULL, //1
	NULL, //2
	NULL, //3
	NULL, //4
	NULL, //5
	NULL, //6
	NULL, //7
	NULL, //8
	NULL, //9
	NULL, //10
	NULL, //11
	NULL, //12
	NULL, //13
	NULL, //14
	NULL, //15
	NULL, //16
	NULL, //17
	NULL, //18
	NULL, //19
	NULL, //20
	NULL, //21
	NULL, //22
	NULL, //23
	NULL, //24
	NULL, //25
	NULL, //26
	NULL, //27
	NULL, //28
	NULL, //29
	NULL, //30
	NULL, //31
	NULL, //32
	NULL, //33
	"&quot;", //34
	NULL, //35
	NULL, //36
	NULL, //37
	"&amp;", //38
	"&apos;", //39
	NULL, //40
	NULL, //41
	NULL, //42
	NULL, //43
	NULL, //44
	"&ndash;", //45
	NULL, //46
	NULL, //47
	NULL, //48
	NULL, //49
	NULL, //50
	NULL, //51
	NULL, //52
	NULL, //53
	NULL, //54
	NULL, //55
	NULL, //56
	NULL, //57
	NULL, //58
	NULL, //59
	"&lt;", //60
	NULL, //61
	"&gt;", //62
	NULL, //63
	NULL, //64
	NULL, //65
	NULL, //66
	NULL, //67
	NULL, //68
	NULL, //69
	NULL, //70
	NULL, //71
	NULL, //72
	NULL, //73
	NULL, //74
	NULL, //75
	NULL, //76
	NULL, //77
	NULL, //78
	NULL, //79
	NULL, //80
	NULL, //81
	NULL, //82
	NULL, //83
	NULL, //84
	NULL, //85
	NULL, //86
	NULL, //87
	NULL, //88
	NULL, //89
	NULL, //90
	NULL, //91
	NULL, //92
	NULL, //93
	NULL, //94
	NULL, //95
	NULL, //96
	NULL, //97
	NULL, //98
	NULL, //99
	NULL, //100
	NULL, //101
	NULL, //102
	NULL, //103
	NULL, //104
	NULL, //105
	NULL, //106
	NULL, //107
	NULL, //108
	NULL, //109
	NULL, //110
	NULL, //111
	NULL, //112
	NULL, //113
	NULL, //114
	NULL, //115
	NULL, //116
	NULL, //117
	NULL, //118
	NULL, //119
	NULL, //120
	NULL, //121
	NULL, //122
	NULL, //123
	"&brvbar;", //124
	NULL, //125
	NULL, //126
	NULL, //127
	"&Ccedil;", //128
	"&uuml;", //129
	"&eacute;", //130
	"&acirc;", //131
	"&auml;", //132
	"&agrave;", //133
	"&aring;", //134
	"&ccedil;", //135
	"&ecirc;", //136
	"&euml;", //137
	"&egrave;", //138
	"&iuml;", //139
	"&icirc;", //140
	"&igrave;", //141
	"&Auml;", //142
	"&Aring;", //143
	"&Eacute;", //144
	"&aelig;", //145
	"&AElig;", //146
	"&ocirc;", //147
	"&ouml;", //148
	"&ograve;", //149
	"&ucirc;", //150
	"&ugrave;", //151
	"&yuml;", //152
	"&Ouml;", //153
	"&Uuml;", //154
	"&oslash;", //155
	"&pound;", //156
	"&Oslash;", //157
	"&times;", //158
	NULL, //159
	"&aacute;", //160
	"&iacute;", //161
	"&oacute;", //162
	"&uacute;", //163
	"&ntilde;", //164
	"&Ntilde;", //165
	"&ordf;", //166
	"&ordm;", //167
	"&iquest;", //168
	"&reg;", //169
	NULL, //170
	"&frac12;", //171
	"&frac14;", //172
	"&iexcl;", //173
	"&laquo;", //174
	"&raquo;", //175
	NULL, //176
	NULL, //177
	NULL, //178
	NULL, //179
	NULL, //180
	"&Aacute;", //181
	"&Acirc;", //182
	"&Agrave;", //183
	"&copy;", //184
	NULL, //185
	NULL, //186
	NULL, //187
	NULL, //188
	"&cent;", //189
	"&yen;", //190
	"&not;", //191
	NULL, //192
	"&perp;", //193
	NULL, //194
	NULL, //195
	"&mdash;", //196
	NULL, //197
	"&atilde;", //198
	"&Atilde;", //199
	NULL, //200
	NULL, //201
	NULL, //202
	NULL, //203
	NULL, //204
	NULL, //205
	NULL, //206
	"&curren;", //207
	"&eth;", //208
	"&ETH;", //209
	"&Ecirc;", //210
	"&Euml;", //211
	"&Egrave;", //212
	NULL, //213
	"&Iacute;", //214
	"&Icirc;", //215
	"&Iuml;", //216
	NULL, //217
	"&lceil;", //218
	NULL, //219
	NULL, //220
	NULL, //221
	"&Igrave;", //222
	NULL, //223
	"&Oacute;", //224
	"&szlig;", //225
	"&Ocirc;", //226
	"&Ograve;", //227
	"&otilde;", //228
	"&Otilde;", //229
	"&micro;", //230
	"&thorn;", //231
	"&THORN;", //232
	"&Uacute;", //233
	"&Ucirc;", //234
	"&Ugrave;", //235
	"&yacute;", //236
	"&Yacute;", //237
	"&macr;", //238
	"&acute;", //239
	NULL, //240
	"&plusmn;", //241
	NULL, //242
	"&frac34", //243
	"&para;", //244
	"&sect;", //245
	"&divide;", //246
	"&cedil;", //247
	"&deg;", //248
	"&uml;", //249
	"&middot;", //250
	"&sup1;", //251
	"&sup3;", //252
	"&sup2;", //253
	NULL, //254
	"&nbsp;" //255
};
//Not found &shy;

/**
  * HTMLEntityCode2ascii table
  * made from http://www.w3schools.com/tags/ref_entities.asp
  * and http://www.elcodigoascii.com.ar/codigo-ascii.php
  */
const char *html_entitie_ids[256]={
	NULL, //0
	NULL, //1
	NULL, //2
	NULL, //3
	NULL, //4
	NULL, //5
	NULL, //6
	NULL, //7
	NULL, //8
	NULL, //9
	NULL, //10
	NULL, //11
	NULL, //12
	NULL, //13
	NULL, //14
	NULL, //15
	NULL, //16
	NULL, //17
	NULL, //18
	NULL, //19
	NULL, //20
	NULL, //21
	NULL, //22
	NULL, //23
	NULL, //24
	NULL, //25
	NULL, //26
	NULL, //27
	NULL, //28
	NULL, //29
	NULL, //30
	NULL, //31
	"&#32;", //32
	"&#33;", //33
	"&#34;", //34
	"&#35;", //35
	"&#36;", //36
	"&#37;", //37
	"&#38;", //38
	"&#39;", //39
	"&#40;", //40
	"&#41;", //41
	"&#42;", //42
	"&#43;", //43
	"&#44;", //44
	"&#45;", //45
	"&#46;", //46
	"&#47;", //47
	"&#48;", //48
	"&#49;", //49
	"&#50;", //50
	"&#51;", //51
	"&#52;", //52
	"&#53;", //53
	"&#54;", //54
	"&#55;", //55
	"&#56;", //56
	"&#57;", //57
	"&#58;", //58
	"&#59;", //59
	"&#60;", //60
	"&#61;", //61
	"&#62;", //62
	"&#63;", //63
	"&#64;", //64
	"&#65;", //65
	"&#66;", //66
	"&#67;", //67
	"&#68;", //68
	"&#69;", //69
	"&#70;", //70
	"&#71;", //71
	"&#72;", //72
	"&#73;", //73
	"&#74;", //74
	"&#75;", //75
	"&#76;", //76
	"&#77;", //77
	"&#78;", //78
	"&#79;", //79
	"&#80;", //80
	"&#81;", //81
	"&#82;", //82
	"&#83;", //83
	"&#84;", //84
	"&#85;", //85
	"&#86;", //86
	"&#87;", //87
	"&#88;", //88
	"&#89;", //89
	"&#90;", //90
	"&#91;", //91
	"&#92;", //92
	"&#93;", //93
	"&#94;", //94
	"&#95;", //95
	"&#96;", //96
	"&#97;", //97
	"&#98;", //98
	"&#99;", //99
	"&#100;", //100
	"&#101;", //101
	"&#102;", //102
	"&#103;", //103
	"&#104;", //104
	"&#105;", //105
	"&#106;", //106
	"&#107;", //107
	"&#108;", //108
	"&#109;", //109
	"&#110;", //110
	"&#111;", //111
	"&#112;", //112
	"&#113;", //113
	"&#114;", //114
	"&#115;", //115
	"&#116;", //116
	"&#117;", //117
	"&#118;", //118
	"&#119;", //119
	"&#120;", //120
	"&#121;", //121
	"&#122;", //122
	NULL, //123
	"&#166;", //124
	NULL, //125
	NULL, //126
	NULL, //127
	"&#199;", //128
	"&#252;", //129
	"&#233;", //130
	"&#226;", //131
	"&#228;", //132
	"&#224;", //133
	"&#229;", //134
	"&#231;", //135
	"&#234;", //136
	"&#235;", //137
	"&#232;", //138
	"&#239;", //139
	"&#238;", //140
	"&#236;", //141
	"&#196;", //142
	"&#197;", //143
	"&#201;", //144
	"&#230;	", //145
	"&#198;", //146
	"&#244;", //147
	"&#246;", //148
	"&#242;", //149
	"&#251;", //150
	"&#249;", //151
	"&#255;", //152
	"&#214;", //153
	"&#220;", //154
	"&#248;", //155
	"&#163;", //156
	"&#216;", //157
	"&#215;", //158
	NULL, //159
	"&#225;", //160
	"&#237;", //161
	"&#243;", //162
	"&#250;", //163
	"&#241;", //164
	"&#209;", //165
	"&#170;", //166
	"&#186;", //167
	"&#191;", //168
	"&#174;", //169
	NULL, //170
	"&#189;", //171
	"&#188;", //172
	"&#161;", //173
	"&#171;", //174
	"&#187;", //175
	NULL, //176
	NULL, //177
	NULL, //178
	NULL, //179
	NULL, //180
	"&#193;", //181
	"&#194;", //182
	"&#192;", //183
	"&#169;", //184
	NULL, //185
	NULL, //186
	NULL, //187
	NULL, //188
	"&#162;", //189
	"&#165;", //190
	"&#172;", //191
	NULL, //192
	"&#8869;", //193
	NULL, //194
	NULL, //195
	"&#8212;", //196
	NULL, //197
	"&#227;", //198
	"&#195;", //199
	NULL, //200
	NULL, //201
	NULL, //202
	NULL, //203
	NULL, //204
	NULL, //205
	NULL, //206
	"&#164;", //207
	"&#240;", //208
	"&#208;", //209
	"&#202;", //210
	"&#203;", //211
	"&#200;", //212
	NULL, //213
	"&#205;", //214
	"&#206;", //215
	"&#207;", //216
	NULL, //217
	"&#8968;", //218
	NULL, //219
	NULL, //220
	NULL, //221
	"&#204;", //222
	NULL, //223
	"&#211;", //224
	"&#223;", //225
	"&#212;", //226
	"&#210;", //227
	"&#245;", //228
	"&#213;", //229
	"&#181;", //230
	"&#254;", //231
	"&#222;", //232
	"&#218;", //233
	"&#219;", //234
	"&#217;", //235
	"&#253;", //236
	"&#221;", //237
	"&#175;", //238
	"&#180;", //239
	NULL, //240
	"&#177;", //241
	NULL, //242
	"&#190;", //243
	"&#182;", //244
	"&#167;", //245
	"&#247;", //246
	"&#184;", //247
	"&#176;", //248
	"&#168;", //249
	"&#183;", //250
	"&#185;", //251
	"&#179;", //252
	"&#178;", //253
	NULL, //254
	"&#160;" //255
};
//Not found: &#173;

#define REMOVE_TAGS_LENGTH 2
const char *remove_tags[REMOVE_TAGS_LENGTH]={
	"<style>",
	"<script>"
};

struct HTMLdumper{
    map_t entity_map;
    map_t remove_tags;
};

/**
 * Remove tag options
 */
char *remove_tag_options(char *tag);

/**
 * Create an HTMLdumper
 **/
HTMLdumper *newHTMLdumper();

/**
 * Get the default HTMLdumper
 */
HTMLdumper *getDefaultHTMLdumper(){
    if (HTMLd==NULL) HTMLd=newHTMLdumper();
    return HTMLd;
}

/**
 * Free your default dumper
 */
void freeDefaultHTMLdumper(){
    if (HTMLd!=NULL){ 
        freeHTMLdumper(HTMLd); 
        HTMLd=NULL;
    }
}

/**
 * Create an HTMLdumper
 **/
HTMLdumper *newHTMLdumper(){
    HTMLdumper *d=malloc(sizeof(HTMLdumper));
    unsigned char i,j;
    unsigned char *value;
    char *key;

    d->entity_map=hashmap_new();

    i=0;
    while(1){
        //printf("%d+\n",i);

        if (html_entities[i]!=NULL){
           value=malloc(sizeof(unsigned char));
           *value=i;
           key=malloc(sizeof(char)*(strlen(html_entities[i])+1));
           strcpy(key, html_entities[i]);
           hashmap_put(d->entity_map,key,value);
           //printf("adding by name: %s -> %d\n", key, *value);
        }

        if (html_entitie_ids[i]!=NULL){
           value=malloc(sizeof(unsigned char));
           *value=i;
           key=malloc(sizeof(char)*(strlen(html_entitie_ids[i])+1));
           strcpy(key, html_entitie_ids[i]);
/*
           {
              int *mierda;
              if(hashmap_get(d->entity_map,key,&mierda)==MAP_OK)
                  printf("Duplicate: %s\n",key);
           }		   
*/
           hashmap_put(d->entity_map,key,value);
           //printf("adding by id: %s -> %d\n", key, *value);
        } 
	if (i==255) break; else i=i+1; 	    
    }
	
	
    d->remove_tags=hashmap_new();
    for (i=0;i<REMOVE_TAGS_LENGTH;i++){
       key=malloc(sizeof(char)*(strlen(remove_tags[i])+1));
       strcpy(key, remove_tags[i]);
       int value_size=(strlen(remove_tags[i])+2);
       //printf("value_size %d\n",value_size);
       value=malloc(sizeof(char)*(value_size));
       //strcpy(value, remove_tags[i]);
       //ADDED DAVID
       value[0]=key[0];
       value[1]='/';
       for(j=2;j<value_size-1;j++){
           value[j]=key[j-1];
           //printf("value[%d]=%c - key[%d]=%c\n",j,value[j],j-1,key[j-1]);
       }
       //printf("Saliendo del bucler sin\n");
/*     MONCHO
       for(j=strlen(value)+1;j>=1;j--){
           value[j]=value[j-1];
           printf("strlen=%d; j=%d\n",strlen(value),j);
       }
       value[1]='/';
*/
       value[value_size-1]='\0';
       //printf("adding: %s -> %s\n", key, value);
       hashmap_put(d->remove_tags,key,value);
    }
    return d;
}


char *dumpHTMLtext(HTMLdumper *d, char *htmlcontent){
  char *startpointer=htmlcontent;
  char *endpointer=NULL;
  int content_length=strlen(htmlcontent);
  char *retvalue=malloc(sizeof(char)*(1+content_length));
  char *retpointer=retvalue;
  char *html_entity;
  int html_entity_length;
  unsigned char *ascii_entity;
  int html_tag_length;
  char *html_tag;
  char *search;
  
  //printf("html: begin\n");
  
  while ( startpointer[0]!='\0' ) {
    while ( startpointer[0] != '\0' && startpointer[0] != '<' && startpointer[0] != '&' ) { 
      retpointer[0]=startpointer[0]; 
      startpointer++;
      retpointer++;
    }
    
    //printf("%s\n",startpointer);
    
    if (startpointer[0]=='\0') break;
    else if (startpointer[0]=='<'){
        html_tag_length=0;
        while ( startpointer[html_tag_length] != '>' && startpointer[html_tag_length] != '\0' ) html_tag_length++;
        if (startpointer[html_tag_length] == '\0'){
                wblprintf(LOG_WARNING,"HTML_PARSER","Unclosed tag.\n");
        }else{
                html_tag=malloc(sizeof(char)*(html_tag_length+2));
                memcpy(html_tag,startpointer,html_tag_length+1);
                html_tag[html_tag_length+1]='\0';
                //printf("TAG_before: %s\n",html_tag);
                html_tag=remove_tag_options(html_tag);
                //printf("TAG: %s\n",html_tag);

                if (hashmap_get(d->remove_tags,html_tag,(any_t *)&search)==MAP_OK){ //remove until </tag>
                    int found=0;
                    endpointer=startpointer+html_tag_length+1;
                    //printf("endpointer %s",endpointer);
                    //exit(1);
                    while (!found && endpointer[0]!='\0'){	
                                while(endpointer[0]!='<' && endpointer[0]!='\0') endpointer++;
                                if (endpointer[0]=='\0'){
                                        wblprintf(LOG_WARNING,"HTML_PARSER","Unclosed tag: %s.\n",html_tag);
                                        startpointer=startpointer+strlen(startpointer);
                                }else{
                                        char *hit_start=endpointer;
                                        while(endpointer[0]!='>' && endpointer[0]!='\0') endpointer++;
                                        if (endpointer[0]=='\0'){
                                           wblprintf(LOG_WARNING,"HTML_PARSER","Unclosed tag: %s.\n",html_tag);
                                           startpointer=startpointer+strlen(startpointer);
                                        }else{
                                                char *ntag=malloc((endpointer-hit_start+2)*sizeof(char));
                                                memcpy(ntag,hit_start,endpointer-hit_start+1);
                                                ntag[endpointer-hit_start+1]='\0';

                                                ntag=remove_spaces_and_lower(ntag);
                                                startpointer=endpointer+1;
                                                if (!strcmp(ntag,search)) {
                                                         found=1;
                                                         //printf("end_tag: %s\n",ntag);
                                                }//else{
                                                //	printf("end_tag: %s - search: %s\n",ntag, search);
                                                //}
                                                free(ntag);
                                        }
                                }
                    }
                    /*
                    endpointer=strstr(startpointer,search);

                    if (endpointer==NULL){
                                wblprintf(LOG_WARNING,"HTML_PARSER","Unclosed tag: %s.\n",html_tag);
                                startpointer=startpointer+strlen(startpointer);
                        }else{
                        startpointer=endpointer+strlen(search);
                        }
                        */
                }else{
                    startpointer+=(html_tag_length+1);
                }
            free(html_tag);
            }
    }else if (startpointer[0]=='&'){
		//printf("Recognizing entity: %d - %s\n", strlen(startpointer), startpointer);
		//printf(".\n");
		html_entity_length=0;
		while(startpointer[html_entity_length]!=';' && startpointer[html_entity_length]!='\0')
		   html_entity_length++;
		//printf("end searching.. %d ..\n", html_entity_length);
		
		if (startpointer[html_entity_length]=='\0'){
		    //memcpy(html_entity,startpointer,html_entity_length);
		    startpointer+=(html_entity_length);
			//retpointer+=(html_entity_length);
		    wblprintf(LOG_WARNING,"HTML_PARSER","Unclosed entity.\n");
		}else{
			html_entity=malloc(sizeof(char)*(html_entity_length+2));
			memcpy(html_entity,startpointer,html_entity_length+1);
			html_entity[html_entity_length+1]='\0';
			//printf("entity recognized: %s\n",html_entity);
		
			if (hashmap_get(d->entity_map,html_entity,(any_t *)&ascii_entity)==MAP_OK){
				retpointer[0]=*ascii_entity;
				retpointer++; 
				startpointer+=(html_entity_length+1);	
			}else{
				memcpy(retpointer,startpointer,html_entity_length+1);
				startpointer+=(html_entity_length+1);
				retpointer+=(html_entity_length+1);
				wblprintf(LOG_WARNING,"HTML_PARSER","Unrecognized entity %s.\n",html_entity);
			}
			free(html_entity);
		}
    }
  } 
  
  retpointer[0]='\0';  
  //printf("html: end\n");
  return retvalue;
}

int f(any_t null_element, any_t data, any_t key ){
	free(data);
	free(key);
	return MAP_OK;
}


void freeHTMLdumper(HTMLdumper *d){
	//printf("liberating entity_map\n");
	hashmap_iterate_elements(d->entity_map,f,NULL);
	hashmap_free(d->entity_map);
	
	//printf("liberating remove_tags\n");	
	hashmap_iterate_elements(d->remove_tags,f,NULL);
	hashmap_free(d->remove_tags);
	
	//printf("liberating d\n");
	free(d);
        d=NULL;
}

char *remove_tag_options(char *b){
	char *write_pointer;
	char *read_pointer;
	char *openclose;
	
	if (b[0]=='\0') return b;
	
	read_pointer=b+1;
	write_pointer=b+1;
	while(read_pointer[0]==' ' || read_pointer[0]=='\t' || read_pointer[0]=='\n' || read_pointer[0]=='\r') read_pointer++; 
	if (read_pointer[0]=='/'){
		read_pointer++;
		while(read_pointer[0]==' ' || read_pointer[0]=='\t' || read_pointer[0]=='\n' || read_pointer[0]=='\r') read_pointer++; 
	}
	
	while(read_pointer[0]!=' ' && read_pointer[0]!='\t' && read_pointer[0]!='\n' && read_pointer[0]!='\r' 
	      && read_pointer[0]!='>' && read_pointer[0]!='/' ){
		write_pointer[0]=tolower(read_pointer[0]);
		write_pointer++;
		read_pointer++;		
	}
	
	
	if ((openclose=strstr(read_pointer,"/"))==NULL){
	   write_pointer[0]='>';
	   write_pointer[1]='\0';
    }else{
		//printf("llegó aquí\n");
		int isclosing=1;
		openclose++;
		while(openclose[0]!='>'){
			if(openclose[0]==' ' || openclose[0]=='\t' || openclose[0]=='\n' || openclose[0]=='\r') ;
			else if (openclose[0]=='/') isclosing=1;
			else isclosing=0;
			openclose++;
		}
		if (isclosing){
			write_pointer[0]='/';
			write_pointer[1]='>';
	        write_pointer[2]='\0';
		} else {
	        write_pointer[0]='>';
	        write_pointer[1]='\0';		
		}
	}
	
	return b;
}


