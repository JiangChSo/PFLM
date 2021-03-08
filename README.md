# PFLM

The implementation of PFLM


Install the required packages
```
virtualenv -p /usr/bin/python3 venv
source venv/bin/activate
pip install -r requirements
```

1. Adjust the appropriate gradient dimensions NB_CLASSES in client.py and server.py.

2. Adjust the dropout in server.py for experimental purposes. For example, 10 represents 10 percent of users dropping out of BSVFL.

3. Adjust the timeouts of the five rounds in server.py to the appropriate RTT (Following the two steps above).

4. Execute the sh file.

```
run nodrop.sh
```

Note that the experimental data is saved in BENCHMARK.
Note that the graph is in the folder Plot.
