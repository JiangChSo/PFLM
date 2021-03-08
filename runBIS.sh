#!/bin/bash

pythonCmd=/usr/bin/python

ifname="lo"
limit="100Gbps"

for LATENCY in "5ms" "50ms" "100ms"; do
     
# Remove all network limitations
sudo tc qdisc del dev $ifname root

# Apply network rate and latency limitations
sudo tc qdisc add dev $ifname root handle 1: htb default 12
sudo tc class add dev $ifname parent 1:1 classid 1:12 htb rate $limit ceil $limit
sudo tc qdisc add dev $ifname parent 1:12 netem delay $LATENCY

  
for NB_CLIENTS in 38 39 40 41 42 43 44 45 46 47 48 49 50; do
#for NB_CLIENTS in 3 10 20 30 40 50 60 70 80 90 100; do

	echo "==== $NB_CLIENTS clients ===="
	echo "(Latency: $LATENCY)"

	for i in {1..1}; do
		
		echo "Iteration $i"

		$pythonCmd server.py $NB_CLIENTS BENCHMARK/good_${NB_CLIENTS}c_nodrop_l${LATENCY}.csv &

		sleep 0.5

		# non-crashing clients
		for ((i=0; i<$NB_CLIENTS; i++)); do
    			$pythonCmd client.py & 
		done

		# crashing clients
		#for ((j=0; j<$NB_CRASHING_CLIENTS; j++)); do
		#	$pythonCmd client.py crash & 
		#done

		sleep 500
		echo ""

	done

	echo ""

done

done
