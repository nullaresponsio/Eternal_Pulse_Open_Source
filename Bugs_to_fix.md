In __main__.py:
Remove lines 372 (and surrounding) that are:
    allow_nets, allow_ips = PublicIPFirewallSMB._load_allowlist(args.allowlist)
We remove from line 370 to 373 (approximately):
Original:
    if args.allowlist:
        allow_nets, allow_ips = PublicIPFirewallSMB._load_allowlist(args.allowlist)
    else:
        allow_nets, allow_ips = [], set()
We remove these four lines.
And change the lambda at the top:
Original:
    # Disable allowlist filtering completely
    PublicIPFirewallSMB._allowed = lambda self, t, nets, ips: True
Changed to:
    # Disable allowlist filtering completely
    PublicIPFirewallSMB._allowed = lambda self, t: True
We'll now write the entire fixed __main__.py and the entire scanner.py as provided (without changes) except that we note the scanner.py provided in the prompt is the one at the end.
But note: the scanner.py provided in the prompt is the last code block. We'll output it as is.
However, the scanner.py code block at the end of the prompt is:
    ... (long code for PublicIPFirewallSMB class)
    if __name__ == "__main__":
        ... (argparse and scanning)
We are not changing that.
Let's write the fixed code.
