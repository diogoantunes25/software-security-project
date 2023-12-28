#! /bin/bash
TIMEOUT=1

RED="\e[31m"
GREEN="\e[32m"
ENDCOLOR="\e[0m"

run="python3 py_analyser.py"


run_test() {
	folder=$1
	for name in $(ls "$folder/" | grep py | cut -d . -f 1); do
		echo -n "$name: "
		script="$folder/$name.py"
		patterns="$folder/$name.patterns.json"
		output="$folder/$name.output.json"
		myout="$folder/$name.my.json"
		log="$folder/$name.log"
		timeout $TIMEOUT $run $script $patterns > $myout 2> $log
		if [ $? -eq 0 ];
		then
			./compare $output $myout 
			if [ $? -eq 0 ];
			then
				echo -e "$GREEN success $ENDCOLOR"
			else
				echo -e "$RED failed $ENDCOLOR"
			fi
		else
			echo -e "$RED timeout $ENDCOLOR"
		fi
		
	done
}

echo "Running official tests..."
run_test "slices"

echo ""
echo "Running our tests..."
run_test "tests"
