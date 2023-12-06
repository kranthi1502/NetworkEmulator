# GROUP NAME: 
# VEERENDRA VENKATAKUMAR RIMMALAPUDI - VR22H
# KRANTHI KIRAN KARRA - KK22L

import socket
import select
import time
import sys
import hashlib
import os
import struct
import signal
import threading
import binascii
import random


class Bridge:
    # A dictionary to store instances of bridges is a bridge with same lan-name already exists
    bridge_instances = {}  

    def __init__(self, lan_name, num_ports, learning_timeout=20):
        self.exit_bool = False
        self.addr_file = None
        self.port_file = None
        self.lan_name = lan_name
        self.num_ports = num_ports
        self.connections = {}
        self.learning_timeout = learning_timeout
        self.server_socket = None
        
        signal.signal(signal.SIGINT, self.signal_handler)

        # Check if a bridge with the same lan-name already exists
        addr_file = ".{}.addr".format(lan_name)
        port_file = ".{}.port".format(lan_name)
        if os.path.exists(addr_file) and os.path.exists(port_file):
            print("Bridge with lan-name", lan_name," already exists.")
            sys.exit(1)

        self.accept_thread = threading.Thread(target=self.accept_connections_threaded)
        self.accept_thread.daemon = True

        self.handle_input = threading.Thread(target=self.handle_input_command)
        self.handle_input.daemon = True


    def signal_handler(self,sig, frame):
        self.exit_bool = True
        for client_socket in self.connections.keys():
            client_socket.send(b"Disconnect")
        
        self.server_socket.close()
        print('You pressed Ctrl+C! Bridge is Disconnecting')
        os.remove(self.addr_file)
        os.remove(self.port_file)
        sys.exit(0)


    def calculate_port(self):
        port = random.randint(10000, 19999)
        return port

    def create_bridgeInfo_files(self, port):
        addr_file = ".{}.addr".format(self.lan_name)
        port_file = ".{}.port".format(self.lan_name)
        
        self.addr_file = addr_file
        self.port_file = port_file

        with open(addr_file, 'w') as f:
            f.write('localhost')

        with open(port_file, 'w') as f:
            f.write(str(port))                          

    def process_command(self, command):
        if command == "show sl":
            self.show_self_learning_table()
        elif command == "quit":
            self.shutdown()
        else:
            print("Invalid command. Supported commands: show sl, quit")

    def show_self_learning_table(self):
        # Display the contents of the self-learning table
        print("Self Learning Table Data:")
        for client_socket, info in self.connections.items():
            mac = info['mac']
            timestamp = info['timestamp']
            if mac is not None:
                new_source_mac = ':'.join([mac[i:i+2].upper() for i in range(0, len(mac), 2)])
            else:
                new_source_mac = None
            print("Client Socket:",client_socket.getpeername()," MAC: ",new_source_mac," timestamp: ",timestamp)


    def shutdown(self):
        # Sending a disconnect alert to an existing connected stations
        for client_socket in self.connections.keys():
            client_socket.send(b"Disconnect")
        os.remove(self.port_file)
        os.remove(self.addr_file)
        
        # time.sleep(1)
        print('Bridge is Disconnecting')
        self.exit_bool = True
        self.server_socket.close()
        sys.exit(0)


    def process_frame(self, frame, source_socket):
        print("Processing a Frame")
        if len(frame) == struct.calcsize("!hh6s4s6s4s"):
            # ARP packet
            self.process_arp_packet(frame, source_socket)
        else:
            # Data frame
            self.process_data_frame(frame, source_socket)

    def process_arp_packet(self, arp_packet, source_socket):
        print("Processing an arp_request")
        
        # Unpack the ARP packet
        arp_packet_data = struct.unpack("!hh6s4s6s4s", arp_packet)
        arp_packet_type = arp_packet_data[0]
        source_mac = arp_packet_data[2]
        source_ip = arp_packet_data[3]
        destination_mac = arp_packet_data[4]
        destination_ip = arp_packet_data[5]

        self.connections[source_socket]["mac"] = binascii.hexlify(source_mac).decode()
        self.connections[source_socket]["timestamp"] = time.time()

        if arp_packet_type == 1: # arp-request
            # Send the ARP packet to all other clients
            for client_socket in self.connections.keys():
                if client_socket != source_socket:
                    client_socket.send(arp_packet)
            print("Sending an arp packet to all stations")

        elif arp_packet_type == 2: # arp_reply
            flag=0
            mac = binascii.hexlify(destination_mac).decode()
            for client_socket in self.connections.keys():
                if self.connections[client_socket]['mac'] == mac:
                    client_socket.send(arp_packet)
                    flag=1
            if flag==1:
                print("arp reply packet sent to source")
            # flag is used check if the mac is existing in self learning table, if it is not there then bridge needs to send data to all connected stations
            if flag==0:
                for client_socket in self.connections.keys():
                    if client_socket != source_socket:
                        client_socket.send(arp_packet)
                print("arp reply packet sent to all the connected clients")


    def process_data_frame(self, data_frame, source_socket):
        print("Processing a Data Frame")
        
        data_frame_data = self.extract_data_frame(data_frame)
        destination_mac = data_frame_data[0]
        source_mac = data_frame_data[1]
        source_ip = data_frame_data[2]
        destination_ip = data_frame_data[3]
        message = data_frame_data[4]

        flag =0
        # flag is used check if the mac is existing in self learning table, if it is not there then bridge needs to send data to all connected stations
        for client_socket in self.connections.keys():
            if self.connections[client_socket]['mac'] == destination_mac:
                flag =1
                print("Data Frame sent to destination")
                client_socket.send(data_frame)
        if flag==0:
            for client_socket in self.connections.keys():
                if client_socket != source_socket:
                    client_socket.send(data_frame)
            print("Data Frame sent to destination")

    def extract_data_frame(self, data_frame):

        unpacked_data = struct.unpack("!6s6s", data_frame[:12])  # Adjust the length based on your format
        destination_mac = binascii.hexlify(unpacked_data[0]).decode('utf-8')
        source_mac = binascii.hexlify(unpacked_data[1]).decode('utf-8')
        packet_data = data_frame[12:]

        unpacked_packet = struct.unpack('!4s4s4s', packet_data[:12])
        source_ip = socket.inet_ntoa(unpacked_packet[0])
        destination_ip = socket.inet_ntoa(unpacked_packet[1])
        next_hop_ip = socket.inet_ntoa(unpacked_packet[2])
        message = packet_data[12:]

        return destination_mac, source_mac, source_ip, destination_ip, message

    def handle_timeouts(self):
        while not self.exit_bool:
            if self.exit_bool:
                break
            try:
                current_time = time.time()
                for socket, value in list(self.connections.items()):
                    time_out = value['timestamp']

                    if time_out!=None and current_time - time_out > self.learning_timeout and self.connections[socket]['mac'] is not None:
                        print("\nRemoving an entry from self learning as timeout reached")
                        self.connections[socket]['mac'] = None
            except Exception as e:
                pass
    
    def handle_input_command(self):
        try:
            while not self.exit_bool:
                if self.exit_bool:
                    break
                time.sleep(0.5)
                command = input("Enter a command: ")
                if command:
                    self.process_command(command)
        except EOFError:
            pass
        except Exception as e:
            print("Exception in user input thread: {}".format(e))
    
    def run(self):
        try:
            self.accept_thread.start()
            self.handle_input.start()
            self.handle_timeouts()
            self.accept_thread.join(timeout=1)
            self.handle_input.join(timeout=1)
            sys.exit(0)

        except ConnectionResetError as e:
            print("Connection reset by the remote host: {}".format(e))
            os.remove(self.addr_file)
            os.remove(self.port_file)


    def accept_connections_threaded(self):
        port = self.calculate_port()
        self.create_bridgeInfo_files(port)

        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.bind(('localhost', port))
        self.server_socket.listen(5)
        print("Bridge for LAN '{}' is listening on port {}".format(self.lan_name, port))


        while True:
            if self.exit_bool:
                break
            select_sockets = [self.server_socket] + list(self.connections.keys())
            readable_sockets, _, _ = select.select(select_sockets, [], [])
            for s in readable_sockets:
                if self.exit_bool:
                    break
                if s == self.server_socket:
                    client_socket, _ = s.accept()
                    if len(self.connections) < self.num_ports:
                        self.connections[client_socket] = {'mac': None, 'timestamp': None}
                        client_socket.send(b"accept")
                        local_address = client_socket.getsockname()
                        remote_address = client_socket.getpeername()

                        print("\nClient ",remote_address," connected to local port ",local_address[1])
                    else:
                        client_socket.send(b"reject")
                        client_socket.close()
                else:
                    data = s.recv(1024)
                    try:
                        if not data:
                            local_address = client_socket.getsockname()
                            remote_address = client_socket.getpeername()
                            print("\nClient ",remote_address," disconnected from local port ",local_address[1])
                            s.close()
                            del self.connections[s]
                        elif data.decode('utf-8', 'ignore') == "Check":
                            print("\nClient ",remote_address," disconnected from local port ",local_address[1])
                            s.send(b"Disconnect1")
                            s.close()
                            del self.connections[s]
                        else:
                            if data=="show sl" or data == "quit":
                                self.process_command(data, s)
                            else:
                                self.process_frame(data, s)
                    except Exception as e:
                        pass

def start():
    if len(sys.argv) != 3:
        print("Invalid command for bridge connection. Use: python bridge.py lan-name num-ports")
        return

    lan_name = sys.argv[1]
    num_ports = int(sys.argv[2])

    bridge_instance = Bridge(lan_name, num_ports)
    bridge_instance.run()

if __name__ == '__main__':
    start()
    
