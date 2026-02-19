#!/usr/bin/env bash

IN_DIR="/a2/iot-fixed"
IFACE="enp6s19"
MAX_ITER=100     # configurable number of iterations

counter=1

cd "$IN_DIR" || {
    echo "Failed to enter directory: $IN_DIR"
    exit 1
}

while (( counter <= MAX_ITER )); do
    echo "$(date) Replaying packets, iteration = $counter / $MAX_ITER"

    for file in *.pcap; do
        [[ -e "$file" ]] || {
            echo "No pcap files found"
            break
        }

        echo "Replaying $file"
        tcpreplay -i "$IFACE" -p 500 "$file" > /dev/null
    done

    ((counter++))
done

echo "Completed $MAX_ITER iterations"

