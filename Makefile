all : send_arp

send_arp : main.c
	gcc -o send_arp main.c -lpcap
