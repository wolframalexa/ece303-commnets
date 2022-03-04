import sys
import socket

# scans given ports on a target server. format: "python3 portscan.py hostname [-p start:end]"

# defaults from: https://geekflare.com/default-port-numbers/
defaults = {
	20: "FTP", 21: "FTP", 80: "HTTP", 443: "HTTPS", 389: "LDAP", 636: "LDAP (SSL)", 161: "SNMP", 22: "SSH", 23: "Telnet", 25: "SMTP", 3389: "Microsoft RDP", 53: "DNS Service", 119: "NNTP", 143: "IMAP", 993: "IMAP (SSL)", 53: "DNS", 67: "DHCP server", 68: "DHCP client", 69: "TFTP", 162: "SNMPTRAP", 110: "POP", 123: "NTP", 15: "Netstat", 42: "ARPA", 43: "WHOIS", 49: "TACACS", 88: "Kerbos", 115: "SFTP", 119: "Network News Transfer Protocol", 175: "VMNET", 179: "BGP", 220: "IMAP", 264: "Border Gateway Multicast Protocol", 995: "POP3", 992: "Telnet"}


args = sys.argv
target = socket.gethostbyname(args[1]) # open target
start, end = args[3][:-1].split(":")   # get ports range
start = int(start)
end = int(end)

print("Beginning scan...")
numopen = 0
for port in range(start, end + 1): # inclusive of "end" port
	if port in defaults: # get default protocol, if it exists
		print("Port " + str(port) + "'s default protocol is " + defaults[port] )

	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	socket.setdefaulttimeout(1) # faster timeout [1s]

	conn = s.connect_ex((target, port)) # attempt connection to port with socket
	if conn == 0:
		print("Port " + str(port) + " is open")
		numopen += 1
	s.close()

if numopen == 0:
	print("No ports in the selected range are open")

print("Scan complete.")
