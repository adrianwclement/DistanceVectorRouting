#!/usr/bin/env python3
"""
dv.py - simplified Distance Vector routing server (UDP + JSON)
Usage: python dv.py -t <topology-file> -i <routing-update-interval>
"""

import argparse
import json
import socket
import threading
import time
import sys
import os
from math import inf
from collections import defaultdict

LOCK = threading.Lock()
INF = 999999  # treat as infinity for printing/computation

def now():
    return time.time()

class DVServer:
    def __init__(self):
        # These get set after user initializes server
        self.topo_file = None
        self.interval = None

        # Core data structures
        self.servers = {}
        self.my_id = None
        self.my_ip = None
        self.my_port = None

        self.neighbor_costs = {}
        self.neighbors = set()
        self.routing_table = {}
        self.last_heard = {}

        self.packets_received = 0
        self.disable_set = set()
        self.crashed = False

        self.sock = None

        # Threads (created only after initialization)
        self.listen_thread = None
        self.periodic_thread = None
        self.timeout_thread = None

    def initialize(self):
        if not self.topo_file or self.interval is None:
            raise RuntimeError("Server not configured")

        self.parse_topology()
        self.init_socket()
        self.init_routing_table()

        # After initialization, start threads
        self.listen_thread = threading.Thread(target=self.listener, daemon=True)
        self.listen_thread.start()

        self.periodic_thread = threading.Thread(target=self.periodic_sender, daemon=True)
        self.periodic_thread.start()

        self.timeout_thread = threading.Thread(target=self.timeout_checker, daemon=True)
        self.timeout_thread.start()

    def parse_topology(self):
        with open(self.topo_file) as f:
            lines = [
                line.strip()
                for line in f
                if line.strip() and not line.strip().startswith('#')
            ]

        # 1. extract num servers and neighbors
        num_servers = int(lines[0])
        num_neighbors = int(lines[1])

        # 2. parse server entries
        self.servers = {}
        for i in range(2, 2 + num_servers):
            sid, ip, port = lines[i].split()
            sid = int(sid)
            self.servers[sid] = {"ip": ip, "port": int(port)}

        # 3. determine my_id via deterministic port-binding
        for sid, info in self.servers.items():
            try:
                test_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                test_sock.bind((info["ip"], info["port"]))
                test_sock.close()

                self.my_id = sid
                self.my_ip = info["ip"]
                self.my_port = info["port"]
                break
            except OSError:
                continue

        if self.my_id is None:
            raise RuntimeError("Unable to match any server entry to this host.")

        # 4. parse neighbor cost lines
        self.neighbor_costs = {}
        self.neighbors = set()

        base = 2 + num_servers
        for i in range(base, base + num_neighbors):
            myid, neigh, cost = lines[i].split()
            myid = int(myid)
            neigh = int(neigh)
            cost = float('inf') if cost.lower() == "inf" else int(cost)

            if myid != self.my_id:
                continue

            self.neighbor_costs[neigh] = cost
            self.neighbors.add(neigh)

        # 5. initialize last_heard
        now_ts = now()
        for n in self.neighbors:
            self.last_heard[n] = now_ts

    def get_local_ips(self):
        # try to get host IP and localhost forms
        ips = {'127.0.0.1', '0.0.0.0', 'localhost'}
        try:
            hostname = socket.gethostname()
            ips.add(socket.gethostbyname(hostname))
        except Exception:
            pass
        # also include all iface addresses
        try:
            for fam in (socket.AddressFamily.AF_INET,):
                pass
        except Exception:
            pass
        return ips

    def init_socket(self):
        # Bind UDP socket to my_ip/my_port
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # allow reuse
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            bind_ip = "0.0.0.0" if self.my_ip in ("0.0.0.0", "127.0.0.1", "localhost") else self.my_ip
            self.sock.bind((bind_ip, self.my_port))
        except Exception as e:
            print("Failed to bind socket to {}:{} -> {}".format(self.my_ip, self.my_port, e))
            print("Trying to bind to 0.0.0.0:{}".format(self.my_port))
            try:
                self.sock.bind(("0.0.0.0", self.my_port))
            except Exception as e2:
                print("FATAL: cannot bind socket:", e2)
                sys.exit(1)

    def init_routing_table(self):
        # initialize routing table: for each known server in servers set cost=INF, next_hop=-
        for sid in self.servers.keys():
            self.routing_table[sid] = {'cost': INF, 'next_hop': -1}
        # cost to self = 0
        self.routing_table[self.my_id] = {'cost': 0, 'next_hop': self.my_id}

        # set direct neighbors costs
        for n, c in self.neighbor_costs.items():
            self.routing_table[int(n)] = {'cost': c, 'next_hop': int(n)}

    def start(self):
        # spawn threads
        self.listen_thread = threading.Thread(target=self.listener, daemon=True)
        self.listen_thread.start()
        self.periodic_thread = threading.Thread(target=self.periodic_sender, daemon=True)
        self.periodic_thread.start()
        self.timeout_thread = threading.Thread(target=self.timeout_checker, daemon=True)
        self.timeout_thread.start()

        # enter command loop
        self.command_loop()

    def listener(self):
        while True:
            try:
                data, addr = self.sock.recvfrom(65536)
                try:
                    msg = json.loads(data.decode())
                except Exception:
                    continue
                self.handle_incoming(msg, addr)
            except Exception:
                if self.crashed:
                    break
                # otherwise continue listening
                continue

    def handle_incoming(self, msg, addr):
        # NEW: process link_update or crash control message BEFORE normal DV handling
        msg_type = msg.get("type")
        
        if msg_type == "link_update":
            try:
                a = int(msg["from"])
            except Exception:
                return
            try:
                cost = int(msg["cost"]) if msg["cost"] != "inf" else INF
            except Exception:
                cost = INF
            with LOCK:
                self.neighbor_costs[a] = cost
                self.neighbors.add(a)
                self.last_heard.setdefault(a, now())
                self.routing_table[a] = {"cost": cost, "next_hop": a if cost < INF else -1}
            return

        elif msg_type == "crash":
            # neighbor has crashed — mark all links INF and crash this server too
            with LOCK:
                for n in list(self.neighbors):
                    self.neighbor_costs[n] = INF
                    self.disable_set.add(n)
                    if n in self.routing_table:
                        self.routing_table[n]['cost'] = INF
                        self.routing_table[n]['next_hop'] = -1
                self.crashed = True
            print(f"CRASH received from server {msg.get('from')}, shutting down...")
            try:
                self.sock.close()
            finally:
                os._exit(0)

        # Expecting JSON as per our format (normal DV packet)
        try:
            sender_id = int(msg.get('sender_id'))
            sender_ip = msg.get('sender_ip')
            sender_port = int(msg.get('sender_port'))
            dv = msg.get('dv', [])
        except Exception:
            return

        with LOCK:
            # mark last heard
            self.last_heard[sender_id] = now()
            # increment packet count
            self.packets_received += 1
            print(f"RECEIVED A MESSAGE FROM SERVER {sender_id}")

            # ensure we know sender's IP/port mapping
            if sender_id not in self.servers:
                self.servers[sender_id] = {'ip': sender_ip, 'port': sender_port}
            else:
                # update IP/port in case it changed
                self.servers[sender_id]['ip'] = sender_ip
                self.servers[sender_id]['port'] = sender_port

            # Distance to neighbor (direct) from our table:
            cost_to_neighbor = self.neighbor_costs.get(sender_id, INF)
            if sender_id in self.disable_set:
                cost_to_neighbor = INF

            # For each entry in neighbor's DV, attempt relaxation
            changed = False
            for entry in dv:
                try:
                    dest = int(entry['id'])
                    reported_cost = int(entry['cost']) if entry['cost'] != 'inf' else INF
                except Exception:
                    continue
                # skip if our idea of cost to neighbor is INF
                if cost_to_neighbor >= INF:
                    continue
                new_cost = cost_to_neighbor + reported_cost
                if new_cost >= INF:
                    new_cost = INF
                # If dest not in routing table, add it
                if dest not in self.routing_table:
                    self.routing_table[dest] = {'cost': INF, 'next_hop': -1}
                current = self.routing_table[dest]['cost']
                # Simple Bellman-Ford relaxation
                if new_cost < current:
                    self.routing_table[dest]['cost'] = new_cost
                    self.routing_table[dest]['next_hop'] = sender_id
                    changed = True
        # End handle_incoming
        return


    def build_dv_packet(self):
        # Build the dv as list of dicts including this server's view of each dest
        entries = []
        with LOCK:
            for dest, info in self.routing_table.items():
                cost = info['cost']
                if cost >= INF:
                    cost_field = 'inf'
                else:
                    cost_field = int(cost)
                ip = self.servers.get(dest, {}).get('ip', '0.0.0.0')
                port = self.servers.get(dest, {}).get('port', 0)
                entries.append({'id': int(dest), 'ip': ip, 'port': int(port), 'cost': cost_field})
            packet = {
                'sender_id': int(self.my_id),
                'sender_ip': self.my_ip,
                'sender_port': int(self.my_port),
                'dv': entries
            }
        return packet

    def send_to_neighbors(self):
        if self.crashed:
            return
        packet = self.build_dv_packet()
        data = json.dumps(packet).encode()
        with LOCK:
            for n in list(self.neighbors):
                if n in self.disable_set:
                    # don't send to disabled neighbor, but you could still send; spec ambiguous.
                    continue
                # find neighbor ip/port
                info = self.servers.get(int(n))
                if info is None:
                    continue
                try:
                    self.sock.sendto(data, (info['ip'], info['port']))
                except Exception:
                    # ignore send errors
                    continue

    def periodic_sender(self):
        # send initial update immediately? The assignment says servers send periodically; we'll send right away then sleep
        time.sleep(self.interval)
        while not self.crashed:
            # Sleep until next interval but first send
            self.send_to_neighbors()
            time.sleep(self.interval)

    def timeout_checker(self):
        # check for neighbors that have not been heard for 3 consecutive intervals -> set their link cost to INF
        threshold = 3 * self.interval
        while not self.crashed:
            time.sleep(self.interval)
            t = now()
            changed = False
            with LOCK:
                for n in list(self.neighbors):
                    last = self.last_heard.get(n, 0)
                    if (t - last) > threshold:
                        # mark as down
                        if self.neighbor_costs.get(n, INF) != INF:
                            self.neighbor_costs[n] = INF
                            # update routing table entry for the neighbor (don't remove)
                            if n in self.routing_table:
                                self.routing_table[n]['cost'] = INF
                                self.routing_table[n]['next_hop'] = -1
                            changed = True
            # we do not automatically broadcast changed info (assignment: updates only periodic or on step)
            # loop continues

    def command_loop(self):
        # main interactive loop
        try:
            while True:
                cmd = input().strip()
                if not cmd:
                    continue

                parts = cmd.split()

                # ------- SERVER COMMAND (initializes everything) -------
                if parts[0].lower() == "server":
                    if len(parts) != 5 or parts[1] != "-t" or parts[3] != "-i":
                        print(f"{cmd} ERROR: wrong arguments")
                        continue

                    self.topo_file = parts[2]
                    self.interval = float(parts[4])

                    try:
                        self.initialize()
                        print(f"{cmd} SUCCESS")
                    except Exception as e:
                        print(f"{cmd} ERROR: {e}")
                    continue

                # ------- Do not allow ANY other command before init -------
                if self.sock is None:
                    print("ERROR: server not initialized. Run: server -t <file> -i <interval>")
                    continue

                # ------- Existing commands below this point -------
                if parts[0].lower() == 'update':
                    # update <server-ID1> <server-ID2> <Link Cost>
                    if len(parts) != 4:
                        print(f"{cmd} ERROR: wrong arguments")
                        continue
                    a = int(parts[1]); b = int(parts[2]); c = parts[3]
                    cost = INF if c.lower() == 'inf' else int(c)
                    # only modify if this server is a or b
                    if a == self.my_id:
                        with LOCK:
                            self.neighbor_costs[b] = cost
                            self.neighbors.add(b)
                            self.last_heard.setdefault(b, now())
                            self.routing_table[b] = {'cost': cost, 'next_hop': b if cost < INF else -1}

                        # NEW: send a link_update to server b
                        info = self.servers.get(b)
                        if info:
                            control = {
                                "type": "link_update",
                                "from": a,
                                "to": b,
                                "cost": cost
                            }
                            try:
                                self.sock.sendto(json.dumps(control).encode(), (info["ip"], info["port"]))
                            except:
                                pass

                        print(f"{cmd} SUCCESS")
                    elif b == self.my_id:
                        with LOCK:
                            self.neighbor_costs[a] = cost
                            self.neighbors.add(a)
                            self.last_heard.setdefault(a, now())
                            self.routing_table[a] = {'cost': cost, 'next_hop': a if cost < INF else -1}

                        # NEW: send a link_update to server a
                        info = self.servers.get(a)
                        if info:
                            control = {
                                "type": "link_update",
                                "from": b,
                                "to": a,
                                "cost": cost
                            }
                            try:
                                self.sock.sendto(json.dumps(control).encode(), (info["ip"], info["port"]))
                            except:
                                pass

                        print(f"{cmd} SUCCESS")
                    else:
                        # assignment says command is issued to both servers, so if this server isn't one of them it's error
                        print(f"{cmd} ERROR: not a neighbor link for this server")

                elif parts[0].lower() == 'step':
                    # send routing update to neighbors right away
                    self.send_to_neighbors()
                    print(f"{cmd} SUCCESS")
                    
                elif parts[0].lower() == 'packets':
                    with LOCK:
                        val = self.packets_received
                        self.packets_received = 0
                    print(f"{cmd} SUCCESS")
                    print(val)

                elif parts[0].lower() == 'display':
                    with LOCK:
                        # display lines sorted by destination id
                        items = sorted(self.routing_table.items(), key=lambda x: int(x[0]))
                        print(f"{cmd} SUCCESS")
                        for dest, info in items:
                            c = info['cost']
                            if c >= INF:
                                cost_str = 'inf'
                                next_hop = -1
                            else:
                                cost_str = str(int(c))
                                next_hop = info['next_hop']
                            print(f"{dest} {next_hop} {cost_str}")

                elif parts[0].lower() == 'disable':
                    # disable <server-ID> : check if the given server is its neighbor
                    if len(parts) != 2:
                        print(f"{cmd} ERROR: wrong arguments")
                        continue
                    x = int(parts[1])
                    with LOCK:
                        if x in self.neighbors:
                            self.disable_set.add(x)
                            self.neighbor_costs[x] = INF
                            if x in self.routing_table:
                                self.routing_table[x]['cost'] = INF
                                self.routing_table[x]['next_hop'] = -1
                            print(f"{cmd} SUCCESS")
                        else:
                            print(f"{cmd} ERROR: {x} is not a neighbor")

                elif parts[0].lower() == 'crash':
                    # propagate crash to all neighbors first
                    with LOCK:
                        crash_msg = {"type": "crash", "from": self.my_id}
                        for n in list(self.neighbors):
                            info = self.servers.get(n)
                            if info:
                                try:
                                    self.sock.sendto(json.dumps(crash_msg).encode(), (info["ip"], info["port"]))
                                except:
                                    pass
                        # mark all links as down locally
                        for n in list(self.neighbors):
                            self.neighbor_costs[n] = INF
                            self.disable_set.add(n)
                            if n in self.routing_table:
                                self.routing_table[n]['cost'] = INF
                                self.routing_table[n]['next_hop'] = -1
                        self.crashed = True
                    print(f"{cmd} SUCCESS")
                    # close socket and exit
                    try:
                        self.sock.close()
                    except:
                        pass
                    # According to the assignment, neighboring servers must handle this close and set link cost to INF
                    # We'll exit to simulate crash
                    sys.exit(0)
                else:
                    print(f"{cmd} ERROR: unknown command")
        except (EOFError, KeyboardInterrupt):
            print("Shutting down.")
            try:
                self.sock.close()
            except:
                pass
            sys.exit(0)
    
    def start(self):
        # only start the command loop; initialization happens inside it
        self.command_loop()

if __name__ == "__main__":
    server = DVServer()
    server.start()
