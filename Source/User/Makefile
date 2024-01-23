all:
	echo "Targets: clean, build, run"

build:
	gcc user.c -o main

clean:
	rm -f main

run: build
	echo
	sudo ./main ./main.c
	echo