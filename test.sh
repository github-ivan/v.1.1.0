#!/bin/bash

var="valgrind --tool=memcheck --show-reachable=yes --leak-check=full $1 $2"
exec $var;
