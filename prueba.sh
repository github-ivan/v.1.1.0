#!/bin/bash

tiempo=$(echo 
	$(time ( 
		./get_mails.sh/corpus_prueba/ > /dev/null 
		2>&1) 
	2>&1) | 
	awk '{print $2;}')
