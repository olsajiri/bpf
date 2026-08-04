#!/bin/bash
# SPDX-License-Identifier: GPL-2.0

source ./benchs/run_common.sh

set -eufo pipefail

function timer_fires()
{
	echo "$*" | sed -E "s/.*timer-fires\s+([0-9]+\.[0-9]+ ± [0-9]+\.[0-9]+M\/s).*/\1/"
}

summary=$($RUN_BENCH -p1 -c0 "$@" trig-user-ringbuf-timer | tail -n1)
printf "%-20s records %s, ENOSPC %s, timer fires %s\n" "user-ringbuf-timer" \
	"$(hits "$summary")" "$(drops "$summary")" "$(timer_fires "$summary")"
