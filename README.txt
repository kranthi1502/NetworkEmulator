# Network emulator project.

# Bridge
# Run a bridge called cs1 which accepts maximum of 8 stations.
python3 bridge.py cs1 8

# Run a bridge called cs2 which accepts maximum of 8 stations.
python3 bridge.py cs2 8

# Run a bridge called cs3 which accepts maximum of 8 stations.
python3 bridge.py cs3 8


# Stations
interface file is used to connect to bridges.

# Run station A
python3 station.py -no interface.a.txt routing.a.txt hosts.txt

# Run station B
python3 station.py -no interface.b.txt routing.b.txt hosts.txt

# Run station C
python3 station.py -no interface.c.txt routing.c.txt hosts.txt

# Run station D
python3 station.py -no interface.d.txt routing.d.txt hosts.txt

# Run station E
python3 station.py -no interface.e.txt routing.e.txt hosts.txt


# Routers
# Run router R1
python3 station.py -route interface.r1.txt routing.r1.txt hosts.txt

# Run router R2
python3 station.py -route interface.r2.txt routing.r2.txt hosts.txt


Command in Bridge:
show sl -> For self learning table
quit -> To terminate the bridge

Command in Station:
send station_name message  -> to send a message
show arp ->  To display the arp cache data
show pq -> To display the pending queue data 
quit -> to terminate the station
show rtable -> To display the routing table data
show interface -> To display the interface data
show host -> To display the host data


Command in Router:
show arp ->  To display the arp cache data
show pq -> To display the pending queue data 
quit -> to terminate the station
show rtable -> To display the routing table data
show interface -> To display the interface data
show host -> To display the host data

