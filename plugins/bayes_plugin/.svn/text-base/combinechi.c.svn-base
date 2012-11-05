/***************************************************************************
*
*   File    : combinechi.c
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
#include "probabilities.h"
#include "combinechi.h"
#include "logger.h"

long double chi2q(long double x, int wc);

long double combine_by(linklist *list_prob,int ns, int nh){

   // printf("HOLA DESDE COMBINE\n");
    double totmsg=0.0;
    long double s;
    long double h;

    //printf("COMBINECHI NSPAM %d\n",ns);
    //printf("COMBINECHI NHAM %d\n",nh);

    totmsg=ns+nh;
    if (totmsg==0){
        wblprintf(LOG_INFO,"BAYES:","Insufficient messages.");
        return 0;
    }

    s=(ns/totmsg);
    h=(nh/totmsg);
    //printf("Total mensajes %f\n",totmsg);
    //printf("COMBINECHI S %2.2Lf\n",s);
    //printf("COMBINECHI H %2.2Lf\n",h);

    int Sexp=0;
    int Hexp=0;
    int i;
    int count_learned;
    int count;

    count_learned=getlengthlist(list_prob);

    //printf("COMBINECHI: TAM LISTA: %d\n",count_learned);

    if (SIGNIFFICANT_TOKENS>count_learned) count=count_learned;
    else count = SIGNIFFICANT_TOKENS;

    for (i=0;i<count;i++){
        probability *p;
        
        getatlist(list_prob,i,(void *)&p);
        //printf("[%i]",i);
        //printf("ANTES DE: s*(1.0-(p->prob)) %2.50f\n",s);
        //printf("\tp->prob) %2.50f\n",p->prob);

        s=s*(1.0-(p->prob));

        //printf("s*(1.0-(p->prob)) %2.50f\n",s);
        //printf("ANTES DE: h*(p->prob) %2.50f\n",h);
        //printf("\tp->prob) %2.50f\n",p->prob);
        h=h*(p->prob);

        //printf("h %2.50Lf\n",h);
        //printf("h*(p->prob) %2.50Lf\n",h*(p->prob));
        //printf("VALOR DE H: %2.999f\n",h);
        //printf("VALOR DE S: %2.999f\n",s);
        
        if (s<1e-200){
            //printf("if (s<1e-200) %2.50f\n",s<1e-200);
            //double mans=0;
            int *exps=(int *)malloc(sizeof(int));
            *exps=0;
            //printf("s:%Lf\n",s);
            s=frexpl(s,exps);
            Sexp+=(*exps);
            //printf("ANTES FREE:S:%Lf\n",s);
            //printf("ANTES FREE:Exponente de s (exps):%i\n",*exps);
            //printf("ANTES FREE:Sexp:%Lf\n",Sexp);
            free(exps);
            //printf("S:%Lf\n",s);
            //printf("Exponente de s (exps):%i\n",*exps);
            //printf("Sexp:%Lf\n",Sexp);
            
        }
        
        //printf("LLEGA 1-2\n");
        if(h<1e-200){
            //double manh=0;
            int *exph=(int *)malloc(sizeof(int));
            *exph=0;
            //printf("h:%2.999f\n",h);
            h=frexpl(h,exph);
            Hexp+= (*exph);
            free(exph);
            //printf("Entera de h:%2.5Lf\n",h);
            //printf("Exponente de h:%d\n",*exph);
        }
        //printf("Hexp:%i\n",Hexp);
        //printf("SExp:%i\n",Sexp);
    }
    //printf("Valor de H despues del for %2.50Lf \n",h);
    //printf("Valor de S despues del for %2.50f \n",s);
    //printf("Valor de Hexp despues del for %d \n",Hexp);
    //printf("Valor de Sexp despues del for %d \n",Sexp);
    //printf("log(s)= %2.99f\n, Sexp= %2.5f\n, log(2)= %2.50f\n",log(s),(double)Sexp,log(2));
    //printf("log(h)= %2.50Lf\n, Hexp= %2.5Lf\n, log(2)= %2.50Lf\n",logl(h),(long double)Hexp,logl(2));
    s=logl(s)+(long double)Sexp*logl(2);
    //printf("VALOR DE S DESPUES DE LOG %Lf\n",s);
    h=logl(h)+(long double)Hexp*logl(2);
    //printf("VALOR DE H DESPUES DE LOG %Lf\n",h);
    //printf("Valor de H despues del log %2.50f \n",h);
    //printf("Valor de S despues del log %2.50f \n",s);
    //printf("ENTRA EN CHI DE S\n");
    s=1.0-chi2q(-2.0*s,count);
    //printf("VALOR CHI DE s %Lf\n",s);
    //printf("Valor de S despues del chi %2.50f \n",s);
    //printf("ENTRA EN CHI DE H\n");
    h=1.0-chi2q(-2.0*h,count);
    //printf("h %2.99Lf\n",h);
    //printf("Valor de H despues del chi %2.50f \n",h);
    //printf("s %2.99Lf\n",s);
    //printf("s-h %2.99Lf\n",((s-h)+1.0)/2.0);

    return ((s-h)+1.0)/2.0;
}

long double chi2q(long double x, int wc){
    long double m;
    long double sum;
    long double term;

    m= x/2.0;
    //printf("VALOR DE Entrada chi %2.99Lf\n",m);
    sum=exp(0.0-m);
    //printf("VALOR DE exp(0-m) %2.50f\n",sum);
    term=sum;
    int i;
    for (i=0;i<wc;i++){
        term=term*(m/(i+1));
        sum=sum+term;
        //printf("SUM: %2.999f\n",sum);
    }
    if (sum<1.0)
        return sum;
    else return 1.0;
}

//int main()
//{
  //  linklist lista;
    //lista = new linkedlist();
    //combine();
//}