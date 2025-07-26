Plan for modification:
- After the scan, for each successful host (in `successful` list), we will attempt to enumerate SMB shares.
- We will do this in a while loop so that we continuously repeat the process (with a sleep interval? but the problem says "in a while loop", so we can do an infinite loop until keyboard interrupt).
- We must be cautious of rate limiting and network congestion. We can add a configurable delay between scans.
We'll add:
1. A new argument `--interval` for the time (in seconds) between scans (default 600 seconds = 10 minutes).
2. Inside the main function, after the existing code (that handles the initial scan and backdoor installation), we will enter a while loop that:
   a. Waits for the interval (if not the first run).
   b. Runs the scan again.
   c. For each successful host, enumerates shares and prints the results (or saves them in the JSON if `--json` is used? But note the requirement is to print debug stats).
   d. We should also print the share enumeration results in a structured way, and include insults if desired.
We note that the existing `enumerate_samba_shares` function (in fingerprint.py) is not shown, but we assume it takes at least a host and returns a list of shares.
We'll structure the output for the share enumeration per host.