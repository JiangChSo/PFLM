# PFLM

This repository is for our Information Sciences 2021 paper "PFLM: Privacy-preserving Federated Learning with Membership Proof". Detailed instructions are described as follows.


Install the required packages
```
virtualenv -p /usr/bin/python3 venv
source venv/bin/activate
pip install -r requirements
```
Install the packages pypbc

1. Adjust the appropriate gradient dimensions NB_CLASSES in client.py and server.py.

2. Adjust the dropout in server.py for experimental purposes. For example, 10 represents 10 percent of users dropping out of PFLM.

3. Adjust the timeouts of the five rounds in server.py to the appropriate RTT (Following the two steps above).

4. Execute the sh file.

```
run nodrop.sh
```

Note that the data recorded in the experiment is saved in BENCHMARK.
Note that the graph is in the folder Plot.
