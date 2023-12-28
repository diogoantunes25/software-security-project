#! /bin/bash

RED="\e[31m"
GREEN="\e[32m"
ENDCOLOR="\e[0m"

run="python3 py_analyser.py"

echo "Running official tests..."

folder="slices"
for name in $(ls "$folder/" | grep py | cut -d . -f 1); do
	echo -n "$name: "
	script="$folder/$name.py"
	patterns="$folder/$name.patterns.json"
	output="$folder/$name.output.json"
	myout="$folder/$name.my.json"
	log="$folder/$name.log"
	$run $script $patterns > $myout 2> $log
	./compare $output $myout 
	if [ $? -eq 0 ];
	then
		echo -e "$GREEN success $ENDCOLOR"
	else
		echo -e "$RED failed $ENDCOLOR"
	fi
done

echo ""
echo "Running our tests..."
