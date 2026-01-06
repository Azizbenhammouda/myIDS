from scapy.all import sniff,IP,TCP,UDP
import time

def print_banner():
    banner = """
                                           
 #### #   # #   #   #     #   ##### ####  
#     #   # #  ##  ###   ###  #     #   # 
#     ##### # # # # # # # # # ####  ####  
#     #   # ##  #  ###   ###  #     #     
 #### #   # #   #   #     #   ##### #       
    """
    print("\033[92m" + banner + "\033[0m")  # Green color
    print("\033[93m[*] Initializing packet capture engine...\033[0m")
    time.sleep(1)
    print("\033[93m[*] Loading network interfaces...\033[0m")
    time.sleep(0.5)
    print("\033[92m[✓] Ready to capture packets!\033[0m\n")
    time.sleep(0.5)
def organize_packet(packet):
  if IP not in packet:
    return None
  packet_data={
    "src_ip":packet[IP].src,
    "dest_ip":packet[IP].dst,
    "protocol":None,
    "port_src":None,
    "port_dst":None
  }
  if TCP in packet:
    packet_data["protocol"]="TCP"
    packet_data["port_src"]=packet[TCP].sport
    packet_data["port_dst"]=packet[TCP].dport
  elif UDP in packet:
    packet_data["protocol"]="UDP"
    packet_data["port_src"]=packet[UDP].sport
    packet_data["port_dst"]=packet[UDP].dport
  else:
     packet_data["protocol"]="OTHER"

  return packet_data
  
def packet_exec(packet):
    organized=organize_packet(packet)
    if organized:
      print (organized)
def start_sniffing(interface=None):
    sniff(iface=interface, prn=packet_exec, store=False)
if __name__ == "__main__":
    print("Starting packet capture...")
    start_sniffing()

 

