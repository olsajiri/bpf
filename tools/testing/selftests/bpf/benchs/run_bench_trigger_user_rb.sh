#!/bin/bash
# SPDX-License-Identifier: GPL-2.0

source ./benchs/run_common.sh

set -eufo pipefail

function timer_fires()
{
	echo "$*" | sed -E "s/.*timer-fires\s+([0-9]+\.[0-9]+ ± [0-9]+\.[0-9]+M\/s).*/\1/"
}

timer_summary=$($RUN_BENCH -p1 -c0 "$@" trig-user-ringbuf-timer | tail -n1)
syscall_summary=$($RUN_BENCH -p1 -c0 "$@" trig-user-ringbuf-syscall | tail -n1)

printf "%-24s records %s, ENOSPC %s, timer fires %s\n" "user-ringbuf-timer" \
	"$(hits "$timer_summary")" "$(drops "$timer_summary")" \
	"$(timer_fires "$timer_summary")"
printf "%-24s records %s, ENOSPC %s\n" "user-ringbuf-syscall" \
	"$(hits "$syscall_summary")" "$(drops "$syscall_summary")"
