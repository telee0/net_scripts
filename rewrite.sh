#!/usr/bin/env bash

# rewrite.sh
#
# Recursively processes *.pcap* w/ tcprewrite (remove VLAN + fix MAC's)
# Support read/write files in a directory structure
#

set -u
set -e  # Remove or comment if you want to continue despite failures

IN_DIR="/a2/iot"
OUT_DIR="/a2/iot-fixed"
FIND_PATTERN="*.pcap*"  # Matches .pcap, .pcapng, .pcap0, .pcap1, ..

echo -n "Starting recursive tcprewrite"

mkdir -p "$OUT_DIR"
cd "$IN_DIR"

count_total=0
count_ok=0
count_ng=0

i=0

while IFS= read -r -d '' file; do
	i=$((i + 1))

	in_file="$file"
	fname="${file##*/}"
	out_file=$(printf "%s/%04d-%s" "$OUT_DIR" "$i" "$fname")
	# out_file=/dev/null

	# echo "[$(date +'%T')] rewriting packets into $out_file"
	printf '%s' "."

	tcprewrite \
		--enet-vlan=del \
        --enet-smac=bc:24:11:59:2b:af \
        --enet-dmac=bc:24:11:a8:12:36 \
        -i "$in_file" \
        -o "$out_file" 2>&1 | grep -v "Warning:" || true

    # Check actual exit status of tcprewrite
    # (the || true makes the pipe always succeed, so we need PIPESTATUS)
	#
    if [ "${PIPESTATUS[0]}" -eq 0 ]; then
        count_ok=$((count_ok + 1))
    else
		echo -e "$in_file: FAILED (exit code ${PIPESTATUS[0]})\n"
        count_ng=$((count_ng + 1))
    fi
done < <(find . -type f -name "$FIND_PATTERN" -size +0c -print0)

count_total=$i

echo
echo "----------------------------------------"
echo "Total found:     $count_total"
echo "OK:              $count_ok"
echo "NG:              $count_ng"
echo
echo "Input folder:    $IN_DIR"
echo "Output folder:   $OUT_DIR"
echo

exit

