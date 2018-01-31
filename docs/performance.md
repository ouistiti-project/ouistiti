# Test configuration:

 - host: Raspberry Pi B+
 - Raspbian
 - target(1) lighttpd 1.4.45 (ssl)
 - target(2) ouistiti conf: VTHREAD=n STATIC_FILE=y others modules =n
 - target(3) ouistiti conf: VTHREAD=n all modules =y
 - target(4) ouistiti conf: VTHREAD_TYPE=fork all modules =y

# Test 1:

6000 requests with 500 concurrents

## Command line

	weighttp -n 6000 -c 500 http://\<server address\>/index.html

## Ouistiti configuration file:

	user="www-data";
	servers=[{
		port = 80;
		keepalivetimeout = 5;
		version="HTTP11";
		maxclients = 2048;
		#maxclients = 512;
		chunksize = 1024;
		...
	}]

## Results:

### target(1):

	finished in 22 sec, 319 millisec and 890 microsec, 268 req/s, 91 kbyte/s
	requests: 6000 total, 6000 started, 6000 done, 6000 succeeded, 0 failed, 0 errored

Memory footprint

	VmPeak:	   10572 kB  
	VmSize:	   10568 kB

### target(2):

	finished in 10 sec, 284 millisec and 82 microsec, 583 req/s, 103 kbyte/s
	requests: 6000 total, 6000 started, 6000 done, 6000 succeeded, 0 failed, 0 errored

Memory footprint

	VmPeak:	    5284 kB  
	VmSize:	    2776 kB

### target(3):

	finished in 13 sec, 113 millisec and 591 microsec, 457 req/s, 90 kbyte/s
	requests: 6000 total, 6000 started, 6000 done, 6000 succeeded, 0 failed, 0 errored

Memory footprint

	VmPeak:	    8668 kB
	VmSize:	    4844 kB

### target(4):

	finished in 152 sec, 548 millisec and 132 microsec, 39 req/s, 7 kbyte/s
	requests: 6000 total, 6000 started, 6000 done, 5829 succeeded, 171 failed, 0 errored

# Test 2:

6000 requests with 500 concurrents with keep-alive

## Command line:

	weighttp -n 6000 -c 500 -k http://10.18.3.155/index.html

## Ouistiti configuration file:

		port = 80;
		keepalivetimeout = 5;
		version="HTTP11";
		maxclients = 2048;
		#maxclients = 512;
		chunksize = 1024;

## Results:

### target(1):

	finished in 10 sec, 381 millisec and 414 microsec, 577 req/s, 187 kbyte/s
	requests: 6000 total, 6000 started, 6000 done, 6000 succeeded, 0 failed, 0 errored

Memory footprint:

	VmPeak:	   10684 kB
	VmSize:	   10680 kB

### target(2):

	finished in 10 sec, 528 millisec and 271 microsec, 569 req/s, 100 kbyte/s
	requests: 6000 total, 6000 started, 6000 done, 6000 succeeded, 0 failed, 0 errored

Memory footprint:

	VmPeak:	    5416 kB
	VmSize:	    2680 kB

### target(3):

	finished in 10 sec, 928 millisec and 317 microsec, 549 req/s, 108 kbyte/s
	requests: 6000 total, 6000 started, 6000 done, 6000 succeeded, 0 failed, 0 errored

Memory footprint

	VmPeak:	    7876 kB
	VmSize:	    4480 kB

### target(4):

	finished in 30 sec, 527 millisec and 654 microsec, 196 req/s, 38 kbyte/s
	requests: 6000 total, 6000 started, 6000 done, 6000 succeeded, 0 failed, 0 errored

Memory footprint

	VmPeak:	    4504 kB + 13552 kB per client
	VmSize:	    4444 kB + 13552 kB per client
