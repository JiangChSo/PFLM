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

for tuple in 8,2 16,4 24,6 32,8 40,10 48,12 56,14 64,16 72,18 80,20 88,22 96,24; do

#for tuple in 5,2  20,6  72,3  95,5 \
#	     21,19  45,5  68,7  90,10 \
#	     40,10  60,15 80,20 \
#	     35,15  53,22 70,30 \
#	     30,20  45,30 60,40 \
#	     26,24  38,37 51,49; do


	IFS=","; set -- $tuple;
   	NB_ALIVE_CLIENTS=$1
       	NB_CRASHING_CLIENTS=$2
   
	NB_CLIENTS=$((NB_ALIVE_CLIENTS + NB_CRASHING_CLIENTS))

	echo "==== $NB_CLIENTS clients ===="
	echo "( $NB_ALIVE_CLIENTS, $NB_CRASHING_CLIENTS )"
	echo ""

	for i in {1..3}; do
		
		echo "Iteration $i"

		$pythonCmd server.py $NB_CLIENTS BENCHMARK/20dropout/benchmark_${NB_CLIENTS}c_drop_${NB_ALIVE_CLIENTS}_${NB_CRASHING_CLIENTS}.csv &

		sleep 0.5

		# non-crashing clients
		for ((i=0; i<$NB_ALIVE_CLIENTS; i++)); do
    			$pythonCmd client.py & 
		done

		# crashing clients
		for ((j=0; j<$NB_CRASHING_CLIENTS; j++)); do
			$pythonCmd client.py crash & 
		done

		sleep 500
		echo ""

	done

	echo ""

done

done
