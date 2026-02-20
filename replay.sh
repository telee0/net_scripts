#!/usr/bin/env bash

IN_DIR="/a2/iot"
OUT_DIR="/a2/iot-fixed"
FIND_PATTERN="*.pcap*"  # Matches .pcap, .pcapng, .pcap0, .pcap1, ..
LOG_FILE="replay.log"
IFACE="enp6s19"
MAX_ITER=100     # configurable number of iterations
PPS="2000"

cd "$OUT_DIR" || {
    echo "Failed to enter directory: $OUT_DIR"
    exit 1
}

counter=1

while (( counter <= MAX_ITER )); do
	echo "Replaying packets, iteration = $counter / $MAX_ITER"
	echo
	find . -maxdepth 1 -type f -name "$FIND_PATTERN" -print0 \
	| sort -z \
	| while IFS= read -r -d '' file; do
		echo "[$(date +'%T')] replaying $file"
		tcpreplay -i "$IFACE" -p "$PPS" "$file"
	done
    ((counter++))
done

echo
echo "Completed $MAX_ITER iterations"
echo

exit

