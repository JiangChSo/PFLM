#!/bin/bash

pythonCmd=/usr/bin/python

ifname="lo"
limit="100Gbps"

for LATENCY in "5ms"; do
     
# Remove all network limitations
sudo tc qdisc del dev $ifname root

# Apply network rate and latency limitations
sudo tc qdisc add dev $ifname root handle 1: htb default 12
sudo tc class add dev $ifname parent 1:1 classid 1:12 htb rate $limit ceil $limit
sudo tc qdisc add dev $ifname parent 1:12 netem delay $LATENCY

  
#NB_CLIENTS=40
for NB_CLIENTS in 10 20 30 40 50 60 70 80 90 100 110 120; do

	echo "==== $NB_CLIENTS clients ===="
	echo "(Latency: $LATENCY)"

	for i in {1..3}; do
		
		echo "Iteration $i"

		$pythonCmd server.py $NB_CLIENTS BENCHMARK/nodropout/good_${NB_CLIENTS}c_nodrop_l${LATENCY}.csv &

		sleep 0.5

		# non-crashing clients
		for ((i=0; i<$NB_CLIENTS; i++)); do
    			$pythonCmd client.py & 
		done

		sleep 500
		echo ""

	done

	echo ""

done

done
