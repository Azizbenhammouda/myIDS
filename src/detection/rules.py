from collections import defaultdict
from datetime import datetime, timedelta


connection_tracker=defaultdict(lambda:{"count":0,"last seen":None,"port":set()})
failed_login_tracker=defaultdict(int)

def track_connections(src_ip,port):
      now=datetime.now()
      tracker=connection_tracker[src_ip]


def ssh_brute_force(packet):
      alerts=[]
      #possible SSH
      if packet["dst_port"]==22:
            return "[ALERT] Possible SSH access from"+received["src_ip"]+"->"+ received["dest_ip"]
  
      