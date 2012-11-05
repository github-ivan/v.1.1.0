#!/bin/bash

path=$(echo "$1");


for i in $(ls $path)
do
 newpath=$(echo "$path/$i.eml");
 oldpath=$(echo "$path/$i");
 mv $oldpath $newpath;
 #echo "mv $oldpath to $newpath"
done;
