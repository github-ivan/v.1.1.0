
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h> 
#include <sys/socket.h>
#include <netinet/in.h>
#include <pthread.h>
#include <cpluff.h>
#include <locale.h>
#include <signal.h>
#include <getopt.h>
#include "fileutils.h"
#include "iniparser.h"
#include "string_util.h"
#include "logger.h"
#include "errno.h"


#define NUM_THREADS 5
#define WIREBRUSH_DEFAULT_PORT 3030

//TYPE OF COMMUNICATION

#define PROCCES -1
#define CHECK -2
#define SYMBOLS -3

#define YES "True"
#define NO "False"

//SPAMC definitions
#define EX_OK           "0 EX_OK"
#define EX_USAGE        "64 EX_USAGE"
#define EX_DATAERR      "65 EX_DATAERR"
#define EX_NOINPUT      "66 EX_NOINPUT"
#define EX_NOUSER       "67 EX_NOUSER"
#define EX_NOHOST       "68 EX_NOHOST"
#define EX_UNAVAILABLE  "69 EX_UNAVAILABLE"
#define EX_SOFTWARE     "70 EX_SOFTWARE"
#define EX_OSERR        "71 EX_OSERR"
#define EX_OSFILE       "72 EX_OSFILE"
#define EX_CANTCREAT    "73 EX_CANTCREAT"
#define EX_IOERR        "74 EX_IOERR"
#define EX_TEMPFAIL     "75 EX_TEMPFAIL"
#define EX_PROTOCOL     "76 EX_PROTOCOL"
#define EX_NOPERM       "77 EX_NOPERM"
#define EX_CONFIG       "78 EX_CONFIG"
//SOCKET I/O ERRORS

#define WRITE_OK -4
#define WRITE_ERROR -5

#define AUTO_LEARN 'a'
#define LEARN_SPAM 's'
#define LEARN_HAM 'h'
#define NO_LEARN 'n'

struct eml_scores{
    float total_score;
    float required_score;
};

typedef struct eml_scores eml_scores;

//SOCKET IO FUNCTIONS;

void start_daemon(int portno,cp_context_t *ctx);
int response_process(int sock,char *errorinfo, char *spam,float score, float required, char *rules, char *msj);
int response_symbols(int sock, char *errorinfo, char *spam, float score, float required, char *rules);
int response_check(int sock, char *errorinfo, char *spam, float score, float required);
int response_headers(int sock,char *errorinfo, char *spam,float score, float required, char *rules, char *msj);
int response_ping(int sock);

int free_pthreads(any_t nullpointer, any_t data, any_t key);
char *obtain_headers(char *msj);
eml_scores *parse_scores(char *report);
void sigint(int sig);
void free_parsed_scores(eml_scores *scores);
void printhelp();

//int wait_for_threads(any_t nullpointer, any_t data);
//int wait_for_threads(any_t nullpointer, any_t data, any_t key);

//WB4SPAM MAIN VALUES
        
char **datainterchangearea=NULL;
pthread_mutex_t mutex4data;
pthread_mutex_t mutex4numthreads;
map_t running_threads=NULL;
int sockfd;
cp_context_t *ctx=NULL;

#define CMS_PLUGIN_LIST "wb4cms_plugins.list"
#define SPAM_PLUGIN_LIST "wb4spam_plugins.list"
#define EMAIL_CONTENT datainterchangearea[0]
#define EMAIL_REPORT datainterchangearea[1]
#define EMAIL_SCORES datainterchangearea[2]
#define LEARN_METHOD datainterchangearea[3]
#define PROGRAM_TYPE datainterchangearea[4]

#define CMS_FILTER 1
#define SPAM_FILTER 0

#define LEARN_MESSAGE -1
#define FORGET_MESSAGE -2
#define HAM_MESSAGE -3
#define SPAM_MESSAGE -4


//WB4SPAM MAIN FUNCTIONS

void handle_fatal_error(const char *msg);
void initialize();
cp_context_t *new_context();
char *program_type=NULL;
void load_plugins(cp_context_t *ctx, char *plugin_list);
void start_plugin(char *args[], cp_context_t *ctx, const char *plugin);

void *manage_conection(void *_sock); /* function prototype */
//void *manage_conection3(void *_sock); /* function prototype */

//PROTOCOL MESSAGE STRUCTURE

struct tinput{
    char *header_info;
    long int message_lenght;
    char *messaje;
    char *user_info;
};

typedef struct tinput tinput;

struct socket_data{
    int socket;
    pthread_t *thread;
    char *thread_id;
    pthread_mutex_t mutex4email;
    pthread_mutex_t mutex4numthreads;
    pthread_mutex_t mutex4threads;
    map_t running_threads;
    int *num_threads;
    cp_context_t *ctx;
    char **datainterchangearea;
    int newsockfd;
};

typedef struct socket_data socket_data;

int main(int argc, char *argv[]){
    
    int op;
    int portno=WIREBRUSH_DEFAULT_PORT;
    char learn_option=NO_LEARN;
    char *learn_method=NULL;
    char *plugin_path=SPAM_PLUGIN_LIST;
    program_type=strstr(argv[0],"wb4");
    static struct option op_largas[] =
    {
        { "port",       required_argument,      NULL,   'p' },
        { "learn",      required_argument,      NULL,   'l' },
        { "help",       no_argument,            NULL,   'h' },        
        { NULL,         0,                      NULL,   0   }
    };
    
    while((op = getopt_long(argc, argv,"p:l:h",op_largas,NULL))!=-1){
        switch(op){
            case 'p': if( (portno=atoi(optarg))==0){
                         wblprintf(LOG_WARNING,program_type,"Unable to asign socket port number. Assuming default port\n");
                         portno=WIREBRUSH_DEFAULT_PORT;
                      }
                      break;
            case 'l': learn_method=to_lower_case(optarg);
                      break;             
            case 'h': printhelp(program_type);
                      return EXIT_SUCCESS;
                      break;
            case '?': wblprintf(LOG_CRITICAL,program_type,"Error invalid option. Assuming default configuration\n");          
                      break;
            default : wblprintf(LOG_CRITICAL,program_type,"Error procesing application. Aborting...\n");
                      return EXIT_FAILURE;
        }               
    }
    
    if(learn_method!=NULL){
        if(!strcmp(learn_method,"auto")) 
            learn_option=AUTO_LEARN;
        else{
            if(!strcmp(learn_method,"ham")) 
                learn_option=LEARN_HAM;
            else 
                if(!strcmp(learn_method,"spam"))
                    learn_option=LEARN_SPAM;
                else{
                    if(!strcmp(learn_method,"none"))
                        learn_option=NO_LEARN;
                    else{
                        wblprintf(LOG_CRITICAL,program_type,"Invalid learning type. Assuming default configuration\n");
                        learn_option=NO_LEARN;
                    }
                }
        }
    }
    
    initialize();
    ctx=new_context();
    
    signal(SIGINT, sigint);
        
    datainterchangearea=malloc(5*sizeof(char *));
    EMAIL_CONTENT=malloc(sizeof(char));
    strcpy(EMAIL_CONTENT,"");
    
    LEARN_METHOD=malloc(sizeof(char)*2);
    sprintf(LEARN_METHOD,"%c",learn_option);
    
    PROGRAM_TYPE=malloc(sizeof(char)+sizeof(int));
    if(strstr(argv[0],"wb4cmsd")!=NULL){
        sprintf(PROGRAM_TYPE,"%d",CMS_FILTER);
        plugin_path=CMS_PLUGIN_LIST;
    }
    else{
        sprintf(PROGRAM_TYPE,"%d",SPAM_FILTER);
        plugin_path=SPAM_PLUGIN_LIST;
    }
        
    EMAIL_REPORT=NULL;
    EMAIL_SCORES=NULL;
    
    load_plugins(ctx,plugin_path);
    
    start_plugin(datainterchangearea, ctx, "es.uvigo.ei.core");
    
    free(EMAIL_CONTENT);
    EMAIL_CONTENT=NULL;
    
    start_daemon(portno,ctx);
    
    (LEARN_METHOD==NULL)?(free(LEARN_METHOD)):(0);
    (PROGRAM_TYPE==NULL)?(free(PROGRAM_TYPE)):(0);
    
    cp_stop_plugins(ctx);

    cp_uninstall_plugins(ctx);   

    cp_destroy_context(ctx);

    cp_destroy();

    return EXIT_SUCCESS; 
}

int response_headers(int sock,char *errorinfo, char *spam,float score, float required, char *rules, char *msj){
    char *msj_header=(char *)malloc((sizeof(char)*strlen(rules)+strlen(spam)+100)+2*sizeof(float));
    sprintf(msj_header,"X-Spam-Checker-Version: Wirebrush4Spam 1.0.0 (2011-10-12)\nX-Spam-Status: %s, score=%2.1lf required=%2.1lf tests=%s",spam,score,required,rules);    
    
    char *spam_header=(char *)malloc(sizeof(char)*(strlen(errorinfo)+strlen(spam)+48)+(2*sizeof(int))+(2*sizeof(float)));
    sprintf(spam_header,"SPAMD/1.4 %s\r\nContent-length: %d\r\nSpam: %s ; %2.1lf / %2.1lf\r\n\r\n",errorinfo,(int)(strlen(msj)+strlen(msj_header)),spam,score,required);
        
    char *original_headers=obtain_headers(msj);
    
    if(original_headers==NULL){
        free(spam_header);
        free(msj_header);
        return WRITE_ERROR;
    }
    
    char *new_msj=malloc(sizeof(char)*(strlen(spam_header)+strlen(msj_header)+strlen(original_headers)+1));
    int written=sprintf(new_msj,"%s%s%s",spam_header,msj_header,original_headers);
    
    free(msj_header);
    free(spam_header);
    
    if(write(sock,new_msj,written)!=written){
        free(new_msj);
        return WRITE_ERROR;
    }    
    free(new_msj);
    
    return WRITE_OK;
}

int response_process(int sock,char *errorinfo, char *spam,float score, float required, char *rules, char *msj){
    
    char *msj_header=(char *)malloc((sizeof(char)*(strlen(rules)+strlen(spam)+100))+sizeof(required)+sizeof(score));
    sprintf(msj_header,"X-Spam-Checker_Version: Wirebrush4Spam 1.1.2 (2012-10-12)\nX-Spam-Status: %s, score=%.1lf required=%.1lf tests=%s",spam,score,required,rules);    
    
    char *spam_header=(char *)malloc(sizeof(char)*(strlen(errorinfo)+strlen(spam)+48)+sizeof(strlen(msj))+(sizeof(required)+sizeof(score)));
    sprintf(spam_header,"SPAMD/1.1 %s\r\nContent-length: %d\r\nSpam: %s ; %.1f / %.1f\r\n\r\n",errorinfo,(int)(strlen(msj)+strlen(msj_header)),spam,score,required);
    
    char *new_msj=(char *)malloc(sizeof(char)*(strlen(msj)+strlen(msj_header)+strlen(spam_header)+1));
    int written=sprintf(new_msj,"%s%s%s",spam_header,msj_header,msj);

    
    free(msj_header);
    free(spam_header);
    
    if(write(sock,new_msj,written)!=written){
        free(new_msj);
        return WRITE_ERROR;
    }
    free(new_msj);

    return WRITE_OK;
}

int response_symbols(int sock, char *errorinfo, char *spam, float score, float required, char *rules){    
    char *spam_header=malloc(sizeof(char)*(strlen(errorinfo)+strlen(spam)+strlen(rules)+48)+sizeof(strlen(rules))+sizeof(score)+sizeof(required));
    int written=sprintf(spam_header,"SPAMD/1.1 %s\r\nContent-length: %d\r\nSpam: %s ; %.1f / %.1f\r\n\r\n%s",errorinfo,(int)strlen(rules),spam,score,required,rules);    

    if( write(sock,spam_header,written)!=written){ 
        free(spam_header);
        return WRITE_ERROR;
    }
    
    free(spam_header);
    return WRITE_OK;
}

int response_check(int sock, char *errorinfo, char *spam, float score, float required){
    char *spam_header=malloc(sizeof(char)*(strlen(errorinfo)+strlen(spam)+30)+2*sizeof(float));
    int written=sprintf(spam_header,"SPAMD/1.1 %s\r\nSpam: %s ; %.1lf / %.1lf\r\n\r\n",errorinfo,spam,score,required);
    
    if( write(sock,spam_header,written)!=written ){ 
        free(spam_header);
        return WRITE_ERROR;
    }
    
    free(spam_header);
    return WRITE_OK;
}

int response_ping(int sock){
    char *spam_header=malloc(sizeof(char)*19);
    int written=strcpy(spam_header,"SPAMD/1.5 0 PONG\r\n");
    
    if( write(sock,spam_header,written)!=written ){ 
        free(spam_header);
        return WRITE_ERROR;
    }
    
    free(spam_header);
    return WRITE_OK;
}

void *manage_conection (void *_sdata)
{
   char buffer[2];
   long int n=0;
   char aux='\0';
   //short countlines=1;
   void *result;
   char *line=malloc(sizeof(char));
   //printf("Malloc line [%s]\n",line);
   socket_data *sdata=(socket_data *)_sdata;
 
   buffer[1]='\0';
   strcpy(line,"");

   tinput *protocol=malloc(sizeof(tinput));
   protocol->header_info=malloc(sizeof(char));
   strcpy(protocol->header_info,"");   
   //printf("Malloc *protocol\n");
   //printf("Malloc protocol->header_info [%s]\n",protocol->header_info);
   
   protocol->message_lenght=0;

   while( read(sdata->socket,&buffer[0],sizeof(char)) > 0 ){
        if(aux=='\n' && buffer[0]=='\r') break;        
        else{   
            if(buffer[0]=='\n'){
                if(strstr(line,"User")!=NULL){
                    int i=1;
                    int length=strlen(line);
                    char *begin=NULL;
                    char *end=&line[length-1];
                    for(;i<length;i++){
                        if(line[(i-1)]==':' && line[i]==' '){
                            begin=&line[i+1];
                            break;
                        }
                    }
                    protocol->user_info=malloc(sizeof(char)*(end-begin+1));
                    memcpy(protocol->user_info,begin,(end-begin)*sizeof(char));
                    protocol->user_info[end-begin]='\0';
                    //printf("Malloc protocol->user_info [%s]\n",protocol->user_info);
                }
                else if(strstr(line,"Content-length:")!=NULL){
                    int i=0;
                    for(;i<strlen(line);i++){
                        if(isdigit(line[i])){
                            protocol->message_lenght*=10;
                            protocol->message_lenght+=line[i]-48;
                        }
                    }
                }
                else if(strstr(line,"Message-class")!=NULL){
                    if(strstr(line,"spam")!=NULL) 
                        sprintf(LEARN_METHOD,"%c",LEARN_SPAM);
                    else sprintf(LEARN_METHOD,"%c",LEARN_HAM);
                }
                else if(strstr(line,"Remove")!=NULL){
                    sprintf(LEARN_METHOD,"%c",FORGET_MESSAGE);
                }
                protocol->header_info=appendstr(protocol->header_info,line);
                //printf("free line [%s]\n",line);
                free(line);
                line=(char *)malloc(sizeof(char));
                //printf("Malloc line [%s]\n",line);
                strcpy(line,"");
            }else line=append(line,buffer[0]);
         
        }
        protocol->header_info=append(protocol->header_info,buffer[0]);
        aux=buffer[0];
    }
    free(line);
    protocol->header_info=appendstr(protocol->header_info,"\r\n");
    protocol->messaje=malloc(sizeof(char)*((protocol->message_lenght)+1));
    
    long int pending_read=protocol->message_lenght;
    int reading=0;
    int buffer_size=0;    
    char *msj_buffer;
    char *isspam;
    eml_scores *escores;
    while(pending_read>0){
        (pending_read>65535)?(buffer_size=65535):(buffer_size=pending_read);
        msj_buffer=(protocol->messaje)+reading;
        if( (n= read(sdata->socket,msj_buffer,buffer_size)) < 0 ){
            wblprintf(LOG_CRITICAL,program_type,"Error reading from socket\n");
            exit(EXIT_FAILURE);
        }       
        reading+=n;
        pending_read-=n;
    }
    
    (!pending_read)?
        (wblprintf(LOG_INFO,program_type,"Message read succesfully from socket\n")):
        (wblprintf(LOG_CRITICAL,"wb4spamd","ERROR reading from socket\n"));
    
    protocol->messaje[protocol->message_lenght]='\0';
    //printf("Malloc protocol->message [%s]\n",protocol->messaje);
    shutdown(sdata->socket,SHUT_RD);
    
    switch((int)(protocol->header_info[0]+protocol->header_info[1]+protocol->header_info[2]+protocol->header_info[3])){
        case 308 : //Process [default option]
                pthread_mutex_lock(&sdata->mutex4email);
                EMAIL_CONTENT=protocol->messaje;
                cp_run_plugins_step(sdata->ctx);
                wblprintf(LOG_INFO,program_type,"Classification done.\n Result: %s %s\n",EMAIL_SCORES,EMAIL_REPORT);
                escores=parse_scores(EMAIL_SCORES);
                (escores->total_score>=escores->required_score)?(isspam=YES):(isspam=NO);
                if(response_process(sdata->socket,EX_OK,isspam,escores->total_score,escores->required_score,EMAIL_REPORT,protocol->messaje)==WRITE_ERROR)
                   wblprintf(LOG_CRITICAL,program_type,"Error could not write on socket\n");
                free_parsed_scores(escores);
                pthread_mutex_unlock(&sdata->mutex4email);
                shutdown(sdata->socket,SHUT_WR);
                break;
        case 315 : //symbols [-y]
                pthread_mutex_lock(&sdata->mutex4email);
                EMAIL_CONTENT=protocol->messaje;
                cp_run_plugins_step(sdata->ctx);
                wblprintf(LOG_INFO,program_type,"Classification done.\n Result: %s %s\n",EMAIL_SCORES,EMAIL_REPORT);
                escores=parse_scores(EMAIL_SCORES);
                (escores->total_score>=escores->required_score)?(isspam=YES):(isspam=NO);
                if(response_symbols(sdata->socket,EX_OK,isspam,escores->total_score,escores->required_score,EMAIL_REPORT)==WRITE_ERROR)
                   wblprintf(LOG_CRITICAL,program_type,"Error could not write on socket\n");
                free_parsed_scores(escores);
                pthread_mutex_unlock(&sdata->mutex4email);                
                shutdown(sdata->socket,SHUT_WR);
                break;
        case 275 : //check [-c option]      
                pthread_mutex_lock(&sdata->mutex4email);
                EMAIL_CONTENT=protocol->messaje;
                cp_run_plugins_step(sdata->ctx);
                wblprintf(LOG_INFO,program_type,"Classification done.\n Result: %s %s\n",EMAIL_SCORES,EMAIL_REPORT);
                escores=parse_scores(EMAIL_SCORES);                
                (escores->total_score>=escores->required_score)?(isspam=YES):(isspam=NO);                
                if(response_check(sdata->socket,EX_OK,isspam,escores->total_score,escores->required_score)==WRITE_ERROR)
                    wblprintf(LOG_CRITICAL,program_type,"Error could not write on socket\n");                
                free_parsed_scores(escores);
                pthread_mutex_unlock(&sdata->mutex4email);                
                shutdown(sdata->socket,SHUT_WR);
                break;
        case 302 : //Ping [-K option]
                wblprintf(LOG_INFO,program_type,"Wirebrush4Spam daemon is alive\n");
                if(response_ping(sdata->socket)==WRITE_ERROR) wblprintf(LOG_CRITICAL,"wb4spamd","Error could not write on socket\n");            
                shutdown(sdata->socket,SHUT_WR);                
                break;
        case 274: //headers [--headers option]
                pthread_mutex_lock(&sdata->mutex4email);
                EMAIL_CONTENT=protocol->messaje;
                cp_run_plugins_step(sdata->ctx);
                wblprintf(LOG_INFO,program_type,"Classification done.\n Result: %s %s\n",EMAIL_SCORES,EMAIL_REPORT);
                escores=parse_scores(EMAIL_SCORES);                
                (escores->total_score>=escores->required_score)?(isspam=YES):(isspam=NO);
                if(response_headers(sdata->socket,EX_OK,isspam,escores->total_score,escores->required_score,EMAIL_REPORT,protocol->messaje)==WRITE_ERROR)
                    wblprintf(LOG_CRITICAL,program_type,"Error could not write on socket\n");
                free_parsed_scores(escores);
                pthread_mutex_unlock(&sdata->mutex4email);
                shutdown(sdata->socket,SHUT_WR);
                break;
        case 305:
                pthread_mutex_lock(&sdata->mutex4email);
                EMAIL_CONTENT=protocol->messaje;
                cp_run_plugins_step(sdata->ctx);
                wblprintf(LOG_INFO,program_type,"Classification done.\n Result: %s %s\n",EMAIL_SCORES,EMAIL_REPORT);
                escores=parse_scores(EMAIL_SCORES);                
                (escores->total_score<=escores->required_score)?(isspam=YES):(isspam=NO);
                if(response_process(sdata->socket,EX_OK,isspam,escores->total_score,escores->required_score,EMAIL_REPORT,protocol->messaje)==WRITE_ERROR)
                    wblprintf(LOG_CRITICAL,program_type,"Error could not write on socket\n");
                free_parsed_scores(escores);                
                pthread_mutex_unlock(&sdata->mutex4email);
                shutdown(sdata->socket,SHUT_WR);
                break;
        default : 
                wblprintf(LOG_CRITICAL,program_type,"Invalid option\n");
                shutdown(sdata->socket,SHUT_WR);
                break;
    }
    
    if(protocol!=NULL) {
        (protocol->header_info!=NULL)?(free(protocol->header_info)):(0);
        if(protocol->messaje!=NULL){
            free(protocol->messaje);
            EMAIL_CONTENT=NULL;
        }
        (protocol->user_info!=NULL)?(free(protocol->user_info)):(0);
        free(protocol);
        protocol=NULL;
    }

    if(hashmap_get(sdata->running_threads,sdata->thread_id,&result)==MAP_MISSING)
        wblprintf(LOG_CRITICAL,program_type,"Error thread ID [%s] not found\n",sdata->thread_id);
    else{ 
        wblprintf(LOG_DEBUG,program_type,"Deleting thread ID [%s]\n",sdata->thread_id);
        hashmap_remove(sdata->running_threads, sdata->thread_id);
        pthread_detach(*sdata->thread);
        free(sdata->thread_id);
        free((pthread_t *)result);
    }
    (*(sdata->num_threads))--;
        
    pthread_mutex_lock(&(sdata->mutex4numthreads));
    
    close(sdata->newsockfd);
    
    pthread_mutex_unlock(&(sdata->mutex4numthreads));

    pthread_mutex_unlock(&(sdata->mutex4email));
    
    if(sdata!=NULL) free(sdata);
    
    pthread_exit(NULL);
}

void initialize(char *program_type){

    cp_set_fatal_error_handler(handle_fatal_error);
    if(cp_init() != CP_OK){
       wblprintf(LOG_CRITICAL,program_type,"Inicialization error. Exiting...\n");
       exit(EXIT_FAILURE);
    }
}

cp_context_t *new_context(){
    cp_status_t status;
    cp_context_t *retval;

    retval=cp_create_context(&status);

    if (retval==NULL){
       wblprintf(LOG_CRITICAL,program_type,"Unable to create context. Exiting...\n");
       exit(EXIT_FAILURE);
    }
    return retval;
}

void load_plugins(cp_context_t *ctx,char *plugin_list){
    FILE *lf;
    char plugindir[256];
    char cwd[768];
    char realpluginpath[1024];
    if(getcwd(cwd, sizeof(cwd)) == NULL) strcpy(cwd,"");

    lf = fopen(plugin_list,"r");
    if (lf==NULL){
       wblprintf(LOG_CRITICAL,program_type,"Unable to load plugin list file (%s). Exiting...\n",plugin_list);
       exit(EXIT_FAILURE);
    }
    while (fgets(plugindir,256,lf) != NULL) {
       cp_plugin_info_t *plugininfo;
       cp_status_t status;
       int i;
 
       //Remove possible trailing newline from plugin location 
       for (i=0; plugindir[i+1] != '\0'; i++);
       if (plugindir[i] == '\n') plugindir[i]='\0';
       strcpy(realpluginpath,cwd);
       strcat(realpluginpath,"/");
       strcat(realpluginpath,plugindir);

       //Load plugin descriptor
       plugininfo = cp_load_plugin_descriptor(ctx, realpluginpath, &status);
       if (plugininfo == NULL) {
           wblprintf(LOG_CRITICAL,program_type,"Unable to load plugin descriptor: %s. Exiting...\n", realpluginpath);
           exit(EXIT_FAILURE);
       }
       //Install plugin descriptor
       status=cp_install_plugin(ctx, plugininfo);
       if(status != CP_OK) {
          wblprintf(LOG_CRITICAL,program_type,"Unable to install plugin: %s. Exiting...\n", plugindir);
          exit(EXIT_FAILURE);
       }
       //Release plugin descriptor information 
       cp_release_info(ctx,plugininfo);
    }

    //Close plugin list file
    fclose(lf);
}

void start_plugin(char *args[], cp_context_t *ctx, const char *plugin){
    
    //Set plugin startup arguments
    cp_set_context_args(ctx, args);

    //Start the core plugin, possibly activating other plugins as well
    //AQUI SE VAN DOS FREE. DONDE COÑO ESTAN¿?!
    if(cp_start_plugin(ctx, plugin)!=CP_OK){
       wblprintf(LOG_CRITICAL,program_type,"Unable to start plugin %s.\n", plugin);
    }
    
}

void handle_fatal_error(const char *msg){
    wblprintf(LOG_CRITICAL,program_type,"Error: %s\n",msg);
    exit(EXIT_FAILURE);
}

void start_daemon(int portno, cp_context_t *ctx)
{
     //int sockfd, newsockfd;//, pid, newsockfd,;
     int newsockfd=0;//, pid, newsockfd,;
     int num_threads=0;
     //int *newsockfd; 
     int cont_emails=0;

     socklen_t clilen;
     
     struct sockaddr_in serv_addr, cli_addr;

     sockfd = socket(AF_INET, SOCK_STREAM, 0);
     if (sockfd < 0) wblprintf(LOG_CRITICAL,program_type,"Unable to open socket\n");

     bzero(&(serv_addr.sin_zero),8);

     serv_addr.sin_family = AF_INET;
     serv_addr.sin_addr.s_addr = INADDR_ANY;
     serv_addr.sin_port = htons(portno);
     
     if (bind(sockfd, (struct sockaddr *) &serv_addr,sizeof(serv_addr)) < 0){ 
        wblprintf(LOG_CRITICAL,program_type,"Error binding\n");
        exit(EXIT_FAILURE);
     }
     newsockfd=listen(sockfd,SOMAXCONN);
     if(newsockfd<0){
         wblprintf(LOG_CRITICAL,program_type,"Error listening on socket\n");
         //printf("Error number: %d\n",errno);
         exit(EXIT_FAILURE);
     }
     clilen = sizeof(cli_addr);
     wblprintf(LOG_INFO,program_type,"Server started succesfully on port %d\n",portno);
     
     pthread_mutex_init(&mutex4data, NULL);
     
     pthread_mutex_init(&mutex4numthreads, NULL);
     
     running_threads=hashmap_new();

     while (1) {
         newsockfd = accept(sockfd, (struct sockaddr *) &cli_addr, &clilen);
         if (newsockfd < 0){ 
             wblprintf(LOG_CRITICAL,program_type,"Error acepting conections\n");
             //printf("Error number: %d\n",errno);
         }
         if (num_threads<=NUM_THREADS){
            cont_emails++;
            printf("Processing email number:%d\n",cont_emails);
            num_threads++; 
            //printf("Malloc socket data\n");;
            socket_data *sdata=malloc(sizeof(socket_data));
            //printf("Malloc socket thread\n");
            pthread_t *socket_thread=malloc(sizeof(pthread_t));
            pthread_t *result;
            //printf("sdata->socket\n");
            sdata->socket=newsockfd;
            
            sdata->thread_id=malloc(sizeof(char)*10);

            sprintf(sdata->thread_id,"%p",(socket_thread));
            //printf("Malloc thread_id %p\n",sdata->thread_id);
            //printf("sdata->datainterchangearea\n");
            sdata->datainterchangearea=datainterchangearea;
            //printf("sdata->mutex4email\n");
            sdata->mutex4email=mutex4data;

            //printf("sdata->mutex4numthreads\n");
            sdata->mutex4numthreads=mutex4numthreads;

            //printf("sdata->num_threads\n");
            sdata->num_threads=&num_threads;
            
            //printf("sdata->running_threads\n");
            sdata->running_threads=running_threads;
            
            //printf("sdata->socket_thread\n");
            sdata->thread=socket_thread;
            
            sdata->newsockfd=newsockfd;
            
            //printf("sdata->ctx\n");
            sdata->ctx=ctx;
            if(hashmap_get(sdata->running_threads,sdata->thread_id,(any_t *)&result)!=MAP_MISSING)
                wblprintf(LOG_CRITICAL,program_type,"Error: Thread id already exist\n");
            else hashmap_put(sdata->running_threads,sdata->thread_id,sdata->thread);
            
            pthread_create(socket_thread,NULL,&manage_conection,(void *)sdata);

         }else wblprintf(LOG_WARNING,program_type,"Maximun number of threads executing\n");
     } /* end of while */
     
     //return EXIT_SUCCESS; /* we never get here */
}

void printhelp(){
    printf("Usage: %s [options]\n",program_type);
    printf("Options:\n");
    printf("  --port \t-p\t<port> [default 3030] \t\tSpecify socket port number.\n");
    printf("  --learn \t-l\t<learn_type>  \t\t\tSpecify learning method.\n");
    printf("  \t\t\t auto  \t\t\t\tEnable autolearn method\n");
    printf("  \t\t\t ham   \t\t\t\tLearn filtered messages as ham\n");
    printf("  \t\t\t spam  \t\t\t\tLearn filtered spam messages as spam\n");    
    printf("  \t\t\t none  \t\t\t\tDisable learning method. [Activated by default]\n");    
    printf("  --help \t-h\t\t\t\t\tPrint help information.\n");
}

int free_pthreads(any_t nullpointer, any_t data, any_t key){
    pthread_join(*((pthread_t *)data),NULL);
    pthread_detach(*((pthread_t *)data));
    free(data);
    free(key);
    return MAP_OK;
}

void sigint(int sig){
    
    wblprintf(LOG_INFO,program_type,"Aborting wb4spam daemon\n");

    if(running_threads!=NULL){
        hashmap_iterate_elements(running_threads,&free_pthreads,NULL);
        hashmap_free(running_threads);
        running_threads=NULL;
    }
    pthread_mutex_destroy(&mutex4data);

    pthread_mutex_destroy(&mutex4numthreads);
    
    wblprintf(LOG_INFO,program_type,"Shutting down plugins...\n");
    if(ctx!=NULL){
 
        close(sockfd);
        
        cp_stop_plugins(ctx);
        
        cp_uninstall_plugins(ctx);
        
        cp_destroy_context(ctx);
        
        cp_destroy();
        
        
        if(datainterchangearea!=NULL){
            if(EMAIL_CONTENT!=NULL) free(EMAIL_CONTENT);
            if(EMAIL_REPORT!=NULL) free(EMAIL_REPORT);
            if(EMAIL_SCORES!=NULL) free(EMAIL_SCORES);
            if(LEARN_METHOD!=NULL) free(LEARN_METHOD);
            if(PROGRAM_TYPE!=NULL) free(PROGRAM_TYPE);
            free(datainterchangearea);
        }
        ctx=NULL;
    }
    exit(EXIT_SUCCESS);
    pthread_exit(NULL);
}

eml_scores *parse_scores(char *report){
    //printf("Malloc eml_scores\n");
    eml_scores *aux=malloc(sizeof(eml_scores));
    char *start_pointer=report;
    char *total_score;
    char *required_score;
    int count=0;
    char *begin=&start_pointer[count];
    char *end;

    if(start_pointer==NULL){
        return NULL;
    }    
    while(start_pointer[count]!='\0'){
        if(start_pointer[count]=='/'){
            end=&start_pointer[(count-1)];
            total_score=malloc(sizeof(char)*(end-begin+1));
            memcpy(total_score,begin,(end-begin)*(sizeof(char)));
            total_score[(count-1)]='\0';
            begin=&start_pointer[count+1];
            aux->total_score=atof(total_score);
            free(total_score);
        }
        if(start_pointer[count+1]=='\0'){
            end=&start_pointer[count];
            required_score=malloc(sizeof(char)*(end-begin+1));
            memcpy(required_score,begin,(end-begin)*sizeof(char));
            required_score[(end-begin)]='\0';
            aux->required_score=atof(required_score);
            free(required_score);
        }
        count++;
    }
    return aux;
}

void free_parsed_scores(eml_scores *scores){
    if(scores!=NULL) free(scores);
}

char *obtain_headers(char *msj){
    char *start_pointer=msj;
    int count=0;
    while(start_pointer[count+1]!='\0'){
        if(start_pointer[count]=='\n' && start_pointer[count+1]!='\n') 
            break;
        else count++;
    }
    if(start_pointer[count+1]=='\0') 
        return NULL;
    else{
        char *begin=&start_pointer[0];
        char *end=&start_pointer[count+1];
        char *aux=malloc(sizeof(char)*(end-begin+1));
        memcpy(aux,begin,(end-begin)*sizeof(char));
        aux[count]='\0';
        return aux;
    }
}