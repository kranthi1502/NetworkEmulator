# GROUP NAME: 
# VEERENDRA VENKATAKUMAR RIMMALAPUDI - VR22H
# KRANTHI KIRAN KARRA - KK22L
import sys
import socket
import select
import threading
import struct
import time
import binascii
import signal
import ipaddress
import traceback

class Station:
    # Constants for ARP packet operations
    ARP_REQUEST = 1
    ARP_REPLY = 2

    # Structure and format for ARP packets
    ARP_PKT_FORMAT = '!hh6s4s6s4s'
    ARPPROTO_IPV4 = 0x0800
    # Structure and format for DATA packets
    DATA_PKT_FORMAT = '!6s6s'

    def __init__(self, station_type,interface_file, routing_table_file, hostname_file):
        self.arp_cache_timeout = 30
        self.exit_bool = False
        if station_type=="-no":
            self.station_type = 1 # station
        else:
            self.station_type = 2 # router

        self.sockets = {}
        self.pending_queue = []
        self.arp_cache = {}

        signal.signal(signal.SIGINT, self.handle_signal)
        
        self.user_input_thread_exit = threading.Event()

        self.accept_thread = threading.Thread(target=self.handle_user_input)
        self.accept_thread.daemon = True

        self.handle_arp_cache_timeout = threading.Thread(target=self.handle_timeouts)
        self.handle_arp_cache_timeout.daemon = True

        self.interface = self.load_interface(interface_file)
        self.routing_table = self.load_routing_table(routing_table_file)
        self.hostname = self.load_hostname(hostname_file)
        
        self.initiate_sockets()


    def handle_signal(self, signum=None, frame=None):
        print("Received signal ",signum,". Shutting down...")

        self.exit_bool = True
        for sock in self.sockets.values():
            sock.close()
        self.user_input_thread_exit.set()  # Signal the user input thread to exit
        sys.exit(0)


    def load_interface(self, filename):
        interface = {}
        with open(filename, 'r') as file:
            for data in file:
                data = data.strip()
                parts = data.split()
                if len(parts) == 5:
                    name, ip, mask, mac, lan = parts
                    interface[name] = {'ip': ip, 'mask': mask, 'mac': mac, 'lan': lan}
        return interface

    def load_routing_table(self, filename):
        routing_table = []
        with open(filename, 'r') as file:
            for data in file:
                data = data.strip()
                parts = data.split()
                if len(parts) == 4:
                    network, next_hop, mask, interface = parts
                    routing_table.append({'network': network, 'next_hop': next_hop, 'mask': mask, 'interface': interface})
        return routing_table

    def load_hostname(self, filename):
        hostname = {}
        with open(filename, 'r') as file:
            for data in file:
                data = data.strip()
                parts = data.split()
                if len(parts) == 2:
                    host, ip = parts
                    hostname[host] = ip
        return hostname

    def initiate_sockets(self):
        for _,details in self.interface.items():
            lan_name = details['lan']
            self.sockets[lan_name] = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sockets[lan_name].setblocking(0)

    def connect_to_bridge(self, lan_name):
        numOfTries = 5  
        retries = 0
        while retries < numOfTries:
            try:
                bridge_addr = self.load_bridge_address(lan_name)
                self.sockets[lan_name].setblocking(1)
                self.sockets[lan_name].settimeout(10)
                self.sockets[lan_name].connect(bridge_addr)
                return True
            except (FileNotFoundError, ConnectionRefusedError, BlockingIOError) as e:
                print("Failed to connect to {} bridge.".format(lan_name))

                retries += 1
            time.sleep(2)

        return False

    def load_bridge_address(self, lan_name):
        addr_file = ".{}.addr".format(lan_name)
        port_file = ".{}.port".format(lan_name)

        with open(addr_file, 'r') as addr, open(port_file, 'r') as port:
            ip = addr.read().strip()
            port_number = int(port.read().strip())
            return (ip, port_number)



    def start(self):
        try:
            print("Station started")
            self.setup_sockets()
            self.accept_thread.start()
            self.handle_arp_cache_timeout.start()
            self.handle_data_frames()
            self.accept_thread.join(timeout=1)
            self.handle_arp_cache_timeout.join(timeout=1)
            sys.exit(0) 
        except Exception as e:
            pass

    def handle_timeouts(self):
        while True:
            if self.exit_bool:
                break
            current_time = time.time()
            keys = list(self.arp_cache.keys())
            for ip in keys:
                timestamp = self.arp_cache[ip]['timestamp']
                if timestamp!=None and current_time - timestamp > self.arp_cache_timeout:
                    print("\nRemoving an entry from arp_cache as timeout reached")
                    del self.arp_cache[ip]


    def setup_sockets(self):
        for lan_name in self.sockets.keys():
            connected = self.connect_to_bridge(lan_name)

            if not connected:
                print("Failed to connect to {} bridge.".format(lan_name))
                sys.exit(1)
            socket_to_read = self.sockets[lan_name]
            initial_message = socket_to_read.recv(1024).decode()
            if initial_message == "reject":
                print("Reached Maximum num of clients for that bridge")    
                self.exit_bool = True
                for sock in self.sockets.values():
                    sock.close()
                print("Sockets Closed")
            else:
                print("Connected to ", lan_name," bridge")

    def handle_data_frames(self):
        while not self.exit_bool:
            time.sleep(2)
            if self.exit_bool:
                break
            try:
                sockets_to_read, _, _ = select.select(self.sockets.values(), [], [])
                for socket_to_read in sockets_to_read:
                    if self.exit_bool:
                        break
                    try:
                            if self.exit_bool:
                                break
                            data_frame = socket_to_read.recv(1024)
                            if data_frame.decode('utf-8', 'ignore') == "Disconnect" or data_frame.decode('utf-8', 'ignore') == "Disconnect1":
                                if data_frame.decode('utf-8', 'ignore') == "Disconnect":
                                    print("One bridge was disconnected so correponding was closing")
                                for key,sock in self.sockets.items():
                                    if sock==socket_to_read:
                                        if data_frame.decode('utf-8', 'ignore') == "Disconnect":
                                            print("Socket connection Closed")
                                        sock.close()
                                        del self.sockets[key]
                                        if len(self.sockets) == 0:
                                            self.exit_bool = True    
                            else:
                                if data_frame:
                                    if len(data_frame) == struct.calcsize(self.ARP_PKT_FORMAT):
                                        self.process_arp_packet(data_frame)
                                    else:
                                        self.process_data_frame(data_frame)
                    except EOFError:
                        pass
                    except Exception as e:
                        pass
            except Exception as e:
                pass


    def process_arp_packet(self, arp_packet):
        print("in process_arp_packet")
        if len(arp_packet) == struct.calcsize(self.ARP_PKT_FORMAT):
            
            arp_packet_data = struct.unpack(self.ARP_PKT_FORMAT, arp_packet)
            arp_packet_type = arp_packet_data[0]
            source_mac = arp_packet_data[2]
            source_ip = arp_packet_data[3]
            destination_mac = arp_packet_data[4]
            destination_ip = arp_packet_data[5]

            if arp_packet_type == self.ARP_REQUEST:
                for interface in self.interface.keys():
                    if ipaddress.ip_address(self.interface[interface]["ip"]) == ipaddress.ip_address(destination_ip):

                        print("Placing data in arp_cache for arp_request")
                        new_source_mac = binascii.hexlify(source_mac).decode()
                        new_source_mac = ':'.join([new_source_mac[i:i+2].upper() for i in range(0, len(new_source_mac), 2)])
                        self.arp_cache[socket.inet_ntoa(source_ip)] = {'mac': new_source_mac, 'timestamp': time.time()}
                        print("Sending an arp reply")
                        self.send_arp_reply(source_ip, source_mac, interface, self.interface[interface]["lan"], destination_ip)
            elif arp_packet_type == self.ARP_REPLY:
                print("Processing arp reply")
                destination_ip = socket.inet_ntoa(destination_ip)
                for interface in self.interface.keys():
                    if ipaddress.ip_address(self.interface[interface]["ip"]) == ipaddress.ip_address(destination_ip):
                        pq = self.pending_queue
                        pq = pq[::-1]
                        li = []
                        for item in pq:
                            # print("item:",item)
                            if  ipaddress.ip_address(socket.inet_ntoa(source_ip)) == ipaddress.ip_address(item[2]):
                                message = item[3]
                                new_dest_ip = item[1]
                                ip_packet = item
                                li.append(item)
                                self.pending_queue.remove(item)
                        
                        lan = self.interface[interface]["lan"]

                        source_mac = binascii.hexlify(source_mac).decode()
                        source_mac = ':'.join([source_mac[i:i+2].upper() for i in range(0, len(source_mac), 2)])

                        destination_mac = binascii.hexlify(destination_mac).decode()
                        destination_mac = ':'.join([destination_mac[i:i+2].upper() for i in range(0, len(destination_mac), 2)])

                        for item in li:
                            if self.station_type==2:
                                time.sleep(2)
                            reply_mac = self.extract_mac_from_arp_reply(arp_packet)
                            temp = binascii.hexlify(reply_mac).decode()
                            new_replyMac = ':'.join([temp[i:i+2].upper() for i in range(0, len(temp), 2)])
                            if new_replyMac:
                                print("Placing in arp_cache for ARP_REPLY")
                                self.arp_cache[socket.inet_ntoa(source_ip)] = {'mac': new_replyMac, 'timestamp': time.time()}

                            if len(message) > 0:
                                data_frame = self.create_data_frame(item,source_mac,destination_mac)

                                socket_to_send = self.sockets[lan]
                                socket_to_send.send(data_frame)
                                check = 0
                                for host in self.hostname.keys():
                                    if ipaddress.ip_address(self.hostname[host]) == ipaddress.ip_address(item[1]):
                                        destination_ip_name = host
                                        print("Message sent to {}.".format(destination_ip_name))
                                        break

    def send_arp_reply(self, source_ip, source_mac,interface,lan,new_source_ip):
        destination_ip = source_ip  
        destination_mac = source_mac
        source_mac = self.interface[interface]['mac']

        arp_reply = struct.pack(
            self.ARP_PKT_FORMAT,
            self.ARP_REPLY,
            self.ARPPROTO_IPV4,
            binascii.unhexlify(source_mac.replace(":", "")),
            new_source_ip,
            destination_mac,
            destination_ip
        )

        socket_to_send = self.sockets[lan]
        socket_to_send.send(arp_reply)
        print("arp reply packet sent")

    def send_message(self,destination_ip, message,source_ip=None):
        network_id,next_hop,interface = self.ip_and_subnet(destination_ip)
        lan = self.interface[interface]["lan"]
        if source_ip is None:
            source_ip = self.interface[interface]['ip']
        source_mac = self.interface[interface]['mac']

        if ipaddress.ip_address(next_hop) == ipaddress.ip_address("0.0.0.0"): # same destination is in same lan
            ip_packet = (source_ip,destination_ip,destination_ip,message)
        else: # destination is in different lan
            ip_packet = (source_ip,destination_ip,next_hop,message)
        self.pending_queue.append(ip_packet)
        
        if ipaddress.ip_address(next_hop) == ipaddress.ip_address("0.0.0.0"):
            destination_mac = self.resolve_mac_address(destination_ip,interface,destination_ip,lan)
        else:    
            destination_mac = self.resolve_mac_address(destination_ip,interface,next_hop,lan)

        if destination_mac:
            self.pending_queue.remove(ip_packet)
            data_frame = self.create_data_frame(ip_packet,destination_mac,source_mac)

            socket_to_send = self.sockets[lan]
            socket_to_send.send(data_frame)
            for host in self.hostname.keys():
                if ipaddress.ip_address(self.hostname[host]) == ipaddress.ip_address(destination_ip):
                    destination_ip_name = host
                    print("Message sent to {}.".format(destination_ip_name))
                    break

    def resolve_mac_address(self,destination_ip,interface,next_hop,lan):

        if next_hop in self.arp_cache.keys():
            print("using ARP cache to get the nexthop mac")
            return self.arp_cache[next_hop]["mac"]
        else:
            source_ip = self.interface[interface]['ip']
            source_mac = self.interface[interface]['mac']
        
            arp_request = self.create_arp_request(source_ip,source_mac,next_hop)
            
            socket_to_send = self.sockets[lan]
            print("sending an arp_request")
            socket_to_send.send(arp_request)
        
    def create_arp_request(self, source_ip, source_mac, next_hop_ip):
        arp_request = struct.pack(
            self.ARP_PKT_FORMAT,
            self.ARP_REQUEST,  # packet_type: ARP request
            self.ARPPROTO_IPV4,
            binascii.unhexlify(source_mac.replace(":", "")),
            socket.inet_aton(source_ip),
            binascii.unhexlify("FFFFFFFFFFFF"),
            socket.inet_aton(next_hop_ip)
        )
        
        return arp_request

    def extract_mac_from_arp_reply(self, arp_reply):
        if len(arp_reply) == struct.calcsize('!hh6s4s6s4s'):
            arp_packet_data = struct.unpack(self.ARP_PKT_FORMAT, arp_reply)
            arp_packet_type = arp_packet_data[0]
            source_mac = arp_packet_data[2]
            source_ip = arp_packet_data[3]
            destination_mac = arp_packet_data[4]
            destination_ip = arp_packet_data[5]
            return source_mac
        else:
            print("Invalid ARP reply packet size")
            return None


    def ip_and_subnet(self,destination_ip):
        destination_ip_int = int(''.join(format(int(x), '08b') for x in destination_ip.split('.')), 2)
        flag=0
        for item in self.routing_table:
            subnet_mask_int = int(''.join(format(int(x), '08b') for x in item["mask"].split('.')), 2)

            result_ip_int = destination_ip_int & subnet_mask_int

            result_ip = '.'.join(str((result_ip_int >> i) & 255) for i in (24, 16, 8, 0))

            ip1_obj = ipaddress.ip_address(result_ip)
            ip2_obj = ipaddress.ip_address(item["network"])

            if ipaddress.ip_address(ip2_obj) == ipaddress.ip_address("0.0.0.0"):
                default_gateway = (result_ip,item["next_hop"],item["interface"])

            if ip1_obj == ip2_obj:
                return result_ip,item["next_hop"],item["interface"]

        return default_gateway 

    def handle_user_input(self):
        try:
            while not self.exit_bool:
                if self.exit_bool:
                    break
                command = input("Enter a command: ")
                if command:
                    self.process_command(command)
        except EOFError:
            pass
        except Exception as e:
            print("Exception in user input thread: {}".format(e))


    def process_command(self, command):
        if self.station_type==1 and command.startswith("send "):
            self.handle_send_command(command)
        elif command == "show arp":
            self.show_arp_cache()
        elif command == "show pq":
            self.show_pending_queue()
        elif command == "show host":
            self.show_hostname_mapping()
        elif command == "show iface":
            self.show_interface_info()
        elif command == "show rtable":
            self.show_routing_table()
        elif command == "quit":
            self.shutdown()
        else:
            print("Invalid command. Station Supported commands: send <destination> <message>, show arp, show pq, show host, show iface, show rtable, quit and Router Supported commands: show arp, show pq, show host, show iface, show rtable, quit")

    def show_arp_cache(self):
        print("ARP Cache Data:")
        for ip, values in self.arp_cache.items():
            print("IP: ",ip, "  Mac:",values["mac"],"   time:",values["timestamp"])
        print(" ")

    def show_pending_queue(self):
        print("Pedning Queue Data:")
        for packet in self.pending_queue:
            print(packet)
        print(" ")

    def show_hostname_mapping(self):
        print("Host Data:")
        for hostname, ip in self.hostname.items():
            print("Hostname: ",hostname,"   IP: ",ip)
        print(" ")

    def show_interface_info(self):
        print("Interface Data:")
        for iface, details in self.interface.items():
            print("Interface: ",iface,"   IP: ",details['ip'],"   MAC: ",details['mac'])
        print(" ")

    def show_routing_table(self):
        print("Routing Table Data:")
        for entry in self.routing_table:
            print("Destination: ",entry['network'],"    Next Hop: ",entry['next_hop'],"    Mask: ",entry['mask'],"     Interface: ",entry['interface'])
        print(" ")

    def shutdown(self):
        print("Station is Closing")

        li = list(self.sockets.values())
        for sock in li:
            time.sleep(1)
            sock.send(b"Check")

        self.exit_bool = True
        self.user_input_thread_exit.set()  # Signal the user input thread to exit
        sys.exit(0)
        

    def handle_send_command(self, command):
        parts = command.split()
        if len(parts) < 3:
            print("Invalid send command. Use: send station_name message")
        else:
            destination_name, message = parts[1], " ".join(parts[2:])
            if destination_name in self.hostname:
                destination_ip = self.hostname[destination_name]
                self.send_message(destination_ip, message)
            else:
                print("Enter valid Station Name")
    

    def process_data_frame(self, data_frame):
        print("processing a data frame")
        data_frame_data = self.extract_data_frame(data_frame)
        destination_mac = data_frame_data[0]
        source_mac = data_frame_data[1]
        source_ip = data_frame_data[2]
        destination_ip = data_frame_data[3]
        message = data_frame_data[4]
        new_source_mac = ':'.join([source_mac[i:i+2].upper() for i in range(0, len(source_mac), 2)])

        if self.station_type==1:
            for interface in self.interface.keys():
                    if ipaddress.ip_address(self.interface[interface]["ip"]) == ipaddress.ip_address(destination_ip):
                        # flag=1
                        for host in self.hostname.keys():
                            if ipaddress.ip_address(self.hostname[host]) == ipaddress.ip_address(source_ip):
                                source_ip_name = host
                                break
                        print("Received message from {}: {}".format(source_ip_name, message.decode()))
                        break
        else:
            print("Received message in Router and transferring message to destination:",message.decode())
            self.send_message(destination_ip, message,source_ip)


    def create_data_frame(self, ip_packet, destination_mac,source_mac):
        packet_data = struct.pack(
        '!4s4s4s',
        socket.inet_aton(ip_packet[0]),
        socket.inet_aton(ip_packet[1]),
        socket.inet_aton(ip_packet[2])
        )

        if isinstance(ip_packet[3], str):
            packet_data += ip_packet[3].encode('utf-8')
        else:
            packet_data += ip_packet[3]

        data_frame = struct.pack(
            self.DATA_PKT_FORMAT,
            binascii.unhexlify(destination_mac.replace(":", "")),
            binascii.unhexlify(source_mac.replace(":", ""))
        ) + packet_data

        return data_frame

    def extract_data_frame(self, data_frame):
        unpacked_data = struct.unpack(self.DATA_PKT_FORMAT, data_frame[:12])  # Adjust the length based on your format
        destination_mac = binascii.hexlify(unpacked_data[0]).decode('utf-8')
        source_mac = binascii.hexlify(unpacked_data[1]).decode('utf-8')

        packet_data = data_frame[12:]

        unpacked_packet = struct.unpack('!4s4s4s', packet_data[:12])
        source_ip = socket.inet_ntoa(unpacked_packet[0])
        destination_ip = socket.inet_ntoa(unpacked_packet[1])
        next_hop_ip = socket.inet_ntoa(unpacked_packet[2])
        message = packet_data[12:]

        return destination_mac, source_mac, source_ip, destination_ip, message

if __name__ == "__main__":
    if len(sys.argv) < 5:
        print("Invalid command for bridge connection. Use: station interface_file routing_table_file hostname_file")
        sys.exit(1)
    
    station_type = sys.argv[1]
    interface_file = sys.argv[2]
    routing_table_file = sys.argv[3]
    hostname_file = sys.argv[4]

    station = Station(station_type,interface_file, routing_table_file, hostname_file)
    station.start()
