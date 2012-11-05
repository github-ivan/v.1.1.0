#!/bin/bash

path=$(echo "$1");


for i in $(ls $path)
do
 newpath=$(echo $i | tr -d '.');
 newpath=$(echo "$path$newpath.eml");
 oldpath=$(echo "$path$i");
 mv $oldpath $newpath;
 #echo "mv $oldpath to $newpath"
done;
