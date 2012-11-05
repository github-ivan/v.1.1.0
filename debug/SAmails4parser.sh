EXPECTED_ARGS=2

if [ $# -ne $EXPECTED_ARGS ]
then
  echo "Usage: `basename $0` {corpus_directory/} {corpus_subdirectory/}"
  exit 0;
fi

./compile_parser.sh;
cont=0;

directory=$(echo "$1$2");
p_directory=$(echo "$1p_$2");
mkdir $p_directory;

for email in $(ls $directory | grep eml)
do
    let cont+=1
    email_path=$(echo "$directory$email");
    p_email_path=$(echo "$p_directory$email");
    email=$(echo "$email");
    echo "Mail num: $cont";
    echo "    email_path: $email_path";
    echo "    email_name: $email";
    echo "    move $email_path to $p_email_path";
    valgrind --tool=memcheck --show-reachable=yes --leak-check=full ./main_parser $email_path;
    sleep 1;
    mv $email_path $p_email_path;
    echo "==================================================================================="
done

