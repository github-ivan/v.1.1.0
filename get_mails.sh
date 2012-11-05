#!/bin/bash

cont=0;
for i in $(ls $1 | grep eml)
do
    let cont+=1 
    path=$(echo "$1$i");
    mail=$(echo "$i");
    echo "Mail num: $cont";
    echo "  path: $path";
    echo "  mail: $mail";
    echo "$cont - $mail" >> salida_emails.txt;
    #printf "$mail;" >> results.csv;
    spamc -p 3030 -c < $path;
    #echo "sleeping for 1 second....";
    #sleep 5;
done




