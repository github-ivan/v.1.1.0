#	LICENSING
#
#       This file is part of WireBrush for Spam project (WB4Spam).
#
#       WB4Spam: An ANSI C is an open source, highly extensible, high performance and 
#       multithread spam filtering platform. It takes concepts from SpamAssassin project
#       improving distinct issues.
#
#       Copyright (C) 2010, by Sing Research Group (http://sing.ei.uvigo.es)
#
#       Wirebrush for Spam is free software; you can redistribute it and/or
#       modify it under the terms of the GNU Lesser General Public License as
#       published by the Free Software Foundation; either version 3 of the
#       License, or (at your option) any later version.
#
#       Wirebrush for Spam is distributed in the hope that it will be useful,
#       but WITHOUT ANY WARRANTY; without even the implied warranty of
#       MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser
#       General Public License for more details.
#
#       You should have received a copy of the GNU Lesser General Public License
#       along with this program.  If not, see <http://www.gnu.org/licenses/>.

CC=gcc -g -O3 -fPIC 
CFLAGS=-c -Wall
CLIBS= -I/usr/include/spf2/ -L/usr/include/spf2/ -lspf2
all: parse_main

parse_main : fileutils.o logger.o html.o hashmap.o linked_list.o iniparser.o string_util.o dictionary.o eml_parser.o header_parser.o cache.o list_files.o spf_plugin.o rxl_plugin.o stack.o parse_func_args.o
	$(CC) $(OPTS) $(CLIBS) list_files.o fileutils.o hashmap.o iniparser.o string_util.o dictionary.o eml_parser.o header_parser.o logger.o cache.o html.o linked_list.o spf_plugin.o rxl_plugin.o stack.o parse_func_args.o main_parser.c -o main_parser $(CLIBS)

parse_func_args.o:
	$(CC) $(CFLAGS) parse_func_args.c -o parse_func_args.o

list_files.o:
	$(CC) $(CFLAGS) list_files.c -o list_files.o

iniparser.o : 
	$(CC) $(CFLAGS) iniparser.c -o iniparser.o

dictionary.o : 
	$(CC) $(CFLAGS) dictionary.c -o dictionary.o

string_util.o:
	$(CC) $(CFLAGS) string_util.c -o string_util.o

html.o:
	$(CC) $(CFLAGS) html.c -o html.o

hashmap.o:
	$(CC) $(CFLAGS) hashmap.c -o hashmap.o

fileutils.o:
	$(CC) $(CFLAGS) fileutils.c -o fileutils.o
	
stack.o:	
	$(CC) $(CFLAGS) stack.c -o stack.o
	
eml_parser.o: stack.o html.o linked_list.o
	$(CC) $(CFLAGS) stack.o html.o linked_list.o eml_parser.c -o eml_parser.o

header_parser.o:
	$(CC) $(CFLAGS) header_parser.c -o header_parser.o

cache.o:
	$(CC) $(CFLAGS) cache.c -o cache.o
	
logger.o: string_util.o
	$(CC) $(CFLAGS) string_util.o logger.c -o logger.o
	
linked_list.o:	
	$(CC) $(CFLAGS) linked_list.c -o linked_list.o

rxl_plugin.o: parse_func_args.o
	$(CC) $(CFLAGS) $(CLIBS) parse_func_args.o rxl_plugin.c -o rxl_plugin.o
	
spf_plugin.o: parse_func_args.o
	$(CC) $(CFLAGS) $(CLIBS) parse_func_args.o spf_plugin.c -o spf_plugin.o
	
clean: 
	rm *.o main_parser
