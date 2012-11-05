./compile_parser.sh
cont=0;
for i in $(ls $1 | grep eml)
do
    let cont+=1
    path=$(echo "$1$i");
    mail=$(echo "$i");
    echo "Mail num: $cont";
    echo "  path: $path";
    echo "  mail: $mail";
    #mv $path 
    sleep 1;
    valgrind --tool=memcheck --show-reachable=yes --leak-check=full ./main_parser $path;
    #echo "$cont - $mail" >> salida_emails.txt;
    #printf "$mail;" >> results.csv;
    #spamc -p 3030 -c < $path;
    #echo "sleeping for 1 second....";
    #sleep 5;
done

