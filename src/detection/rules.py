def packet_receiver(packet):
  received=organize_packet(packet)
  if received:
    #possible SSH
    if received["port_dst"]==22:
      return "[ALERT] Possible SSH access from"+received["src_ip"]+"->"+ received["dest_ip"]