#!/bin/bash

pythonCmd=/usr/bin/python

#ifname="lo"
#limit="100Gbps"

#for LATENCY in 0.5 5 25 50 100 200; do
     
# Remove all network limitations
#sudo tc qdisc del dev $ifname root

# Apply network rate and latency limitations
#sudo tc qdisc add dev $ifname root handle 1: htb default 12
#sudo tc class add dev $ifname parent 1:1 classid 1:12 htb rate $limit ceil $limit
#sudo tc qdisc add dev $ifname parent 1:12 netem delay $LATENCY

for tuple in 450,50 21,19 \
             48,2  45,5 40,10 35,15 30,20 26,24 \
             72,3  68,7 60,15 53,22 45,30 38,37 \
             95,5 90,10 80,20 70,30 60,40 51,49; do

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

	for i in {1..5}; do
		
		echo "Iteration $i"

		$pythonCmd server.py $NB_CLIENTS BENCHMARK/benchmark_${NB_CLIENTS}c_drop_${NB_ALIVE_CLIENTS}_${NB_CRASHING_CLIENTS}.csv &

		sleep 0.5

		# non-crashing clients
		for ((i=0; i<$NB_ALIVE_CLIENTS; i++)); do
    			$pythonCmd client.py & 
		done

		# crashing clients
		for ((j=0; j<$NB_CRASHING_CLIENTS; j++)); do
			$pythonCmd client.py crash & 
		done

		sleep 300
		echo ""

	done

	echo ""

done

#done
