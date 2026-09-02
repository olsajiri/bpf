#!/bin/bash

set -eufo pipefail

def_tests=( \
	usermode-count kernel-count syscall-count \
	user-ringbuf-timer user-ringbuf-syscall \
	unix-socket \
	fentry fexit fmodret \
	rawtp tp \
	kprobe kprobe-multi kprobe-multi-all \
	kretprobe kretprobe-multi kretprobe-multi-all \
)

tests=("$@")
if [ ${#tests[@]} -eq 0 ]; then
	tests=("${def_tests[@]}")
fi

p=${PROD_CNT:-1}

for t in "${tests[@]}"; do
	prod_cnt=$p
	args=(-w2 -d5 -a -c0)
	if [ "$t" = unix-socket ]; then
		prod_cnt=1
		args[-1]=-c1
	fi
	args+=(-p$prod_cnt)
	summary=$(sudo ./bench "${args[@]}" trig-$t | tail -n1 | cut -d'(' -f1 | cut -d' ' -f3-)
	printf "%-20s: %s\n" $t "$summary"
done
