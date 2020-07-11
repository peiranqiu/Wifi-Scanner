from scapy.all import *
import os
import threading

def hopper():
	n = 1
	os.system('airport -z')
	while True:
		os.system('airport -c%d' % (n))
		n = n % 11 + 1
		time.sleep(0.5)

bssids = []    # Found BSSIDs
def handle_packet(pkt):
	if pkt.haslayer(Dot11Beacon):
		bssid = pkt.getlayer(Dot11).addr2
		try:
			ssid = pkt.getlayer(Dot11Elt).info.decode()
			stats = pkt.getlayer(Dot11Beacon).network_stats()
		except:
			return

		if bssid not in bssids:
			bssids.append(bssid)

			if ssid == '' or pkt.getlayer(Dot11Elt).ID != 0:
				print("\033[93m{}\033[00m" .format("Hidden Network Detected"), end = " ")
			else:
				print("Network Detected: %s" % (ssid), end = " ")

			print("BSSID: %s" % (bssid), end = " ")
			print("Channel: %s" % (stats.get("channel")), end = " ")
			print("Crypto: %s" % (stats.get("crypto")))

if __name__ == "__main__":

	thread = threading.Thread(target=hopper, name="hopper")
	thread.daemon = True
	thread.start()

	interface = "en0"
	print('Wifi Scanner Initialized')
	sniff(iface=interface, prn=handle_packet, store=0, count=0, monitor=True)












