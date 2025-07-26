# Standard scan with evasion techniques
python3.13 scanner.py --hosts 192.168.1.1 10.0.0.1 --output results.json

# # Scan without evasion techniques
# python3.13 scanner.py --cidrs 192.168.0.0/24 --no-evasion

# # Async scan with max workers
# python3.13 scanner.py --hosts 172.16.0.1-172.16.0.255 --workers 500 --async