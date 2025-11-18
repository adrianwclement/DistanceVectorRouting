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
from math import inf
from collections import defaultdict

LOCK = threading.Lock()
INF = 999999  # treat as infinity for printing/computation

def now(): return time.time()

class DVServer:
    def __init__(self, topo_file, update_interval):
        self.topo_file = topo_file
        self.interval = float(update_interval)
        # parsed from topology file
        self.servers = {}         # server_id -> {'ip': ip, 'port': port}
        self.my_id = None
        self.my_ip = None
        self.my_port = None

        # neighbor costs (direct links known at startup for *this* host)
        self.neighbor_costs = {}  # neighbor_id -> cost
        self.neighbors = set()    # neighbor ids

        # routing table: dest_id -> {'cost': cost, 'next_hop': next_hop}
        self.routing_table = {}

        # for detecting neighbor absence
        self.last_heard = {}      # neighbor_id -> timestamp of last DV received

        # bookkeeping
        self.packets_received = 0
        self.disable_set = set()  # neighbor ids disabled by 'disable' command
        self.crashed = False

        # UDP socket
        self.sock = None

        # parse topology and init
        self.parse_topology()
        self.init_socket()
        self.init_routing_table()

        # threads control
        self.listen_thread = None
        self.periodic_thread = None
        self.timeout_thread = None

    def parse_topology(self):
        # Support two common file styles:
        # style A (example): first two lines num-servers, num-neighbors then server entries then link lines
        # style B: all necessary lines (server lines and neighbor cost lines).
        lines = []
        with open(self.topo_file) as f:
            for raw in f:
                s = raw.strip()
                if not s: continue
                # ignore comment lines starting with #
                if s.startswith('#'): continue
                tokens = s.split()
                lines.append(tokens)

        # Heuristic: find all 3-token lines that look like server entries: (id ip port)
        # and all 3-token lines that look like link entries: (id1 id2 cost)
        # We'll build servers dict from any token where token[1] is an IP-like token (contains '.')
        server_lines = []
        link_lines = []
        counts = []
        for tokens in lines:
            if len(tokens) >= 1 and all(tok.isdigit() for tok in tokens[:1]):
                counts.append(tokens)
            # server-like: second token has a dot (ip)
            if len(tokens) >= 3 and '.' in tokens[1]:
                server_lines.append(tokens[:3])
            elif len(tokens) >= 3:
                # numeric triple -> link or maybe server with numeric ip (unlikely)
                # decide by whether middle token contains a dot; else treat as link
                link_lines.append(tokens[:3])

        # If server_lines is empty but there were counts and then server lines after counts, try original structure:
        if not server_lines and len(lines) >= 3:
            # maybe lines[2..2+num_servers) are server entries
            try:
                num_servers = int(lines[0][0])
                num_neighbors = int(lines[1][0]) if len(lines) >= 2 else 0
                # servers likely start at index 2
                for i in range(2, 2 + num_servers):
                    if i < len(lines):
                        server_lines.append(lines[i][:3])
                # remaining are links
                for j in range(2 + num_servers, len(lines)):
                    if len(lines[j]) >= 3:
                        link_lines.append(lines[j][:3])
            except Exception:
                pass

        # Build servers map
        for tok in server_lines:
            sid = int(tok[0])
            ip = tok[1]
            port = int(tok[2])
            self.servers[sid] = {'ip': ip, 'port': port}

        # Build link lines as neighbor costs (bidirectional)
        for tok in link_lines:
            try:
                a = int(tok[0]); b = int(tok[1]); c = tok[2]
                if c.lower() == 'inf' or c.lower() == 'infty':
                    cost = INF
                else:
                    cost = int(c)
                # store symmetric in adjacency (but only keep local neighbors later)
                # We'll set neighbor_costs later using my_id
                # For now, record in an adjacency map in case this file is global
                # We'll keep it in a temporary structure
                # use adjacency dict on self for convenience
                if not hasattr(self, 'adj'):
                    self.adj = {}
                self.adj[(a,b)] = cost
                self.adj[(b,a)] = cost
            except Exception:
                continue

        # Now detect which server is "me" by matching one server's ip and port with local host
        # But the assignment expects the host to find its own entry in the topology file without changing the file.
        # We'll try to match by our local machine IPs; as fallback assume the file's server list contains an ID and we
        # prompt the user to choose (but we cannot prompt per instruction). So use environment: choose the first server entry
        # whose ip is local or 127.0.0.1 or '' ; otherwise pick the first server line.
        # We'll attempt to bind to the port of the chosen server id.
        # Choose my_id as the server entry that matches one of the local host IPs (or '127.0.0.1').
        local_ips = self.get_local_ips()
        chosen = None
        for sid,info in self.servers.items():
            if info['ip'] in local_ips or info['ip'] == '127.0.0.1' or info['ip'].startswith('0.0.0.0'):
                chosen = (sid, info)
                break
        if not chosen:
            # fallback: pick the first server entry
            if len(self.servers) == 0:
                raise RuntimeError("Topology file didn't contain any server entries.")
            sid = next(iter(self.servers))
            chosen = (sid, self.servers[sid])

        self.my_id = int(chosen[0])
        self.my_ip = chosen[1]['ip']
        self.my_port = int(chosen[1]['port'])

        # Build neighbor costs based on adjacency if available
        self.neighbor_costs = {}
        if hasattr(self, 'adj'):
            for (a,b),cost in list(self.adj.items()):
                if a == self.my_id:
                    self.neighbor_costs[b] = cost
                    self.neighbors.add(b)

        # If neighbor lines were given explicitly as server's neighbor entries in the file style,
        # e.g., some files list only neighbors for the host, handle that: look for any triple whose first token == my_id.
        for tokens in lines:
            if len(tokens) >= 3:
                try:
                    a = int(tokens[0])
                    b = tokens[1]
                except:
                    continue
                # tokens are ambiguous; detect patterns like "1 2 7" meaning my_id neighbor cost
                if len(tokens) == 3:
                    try:
                        a = int(tokens[0]); b = int(tokens[1]); c = tokens[2]
                        if a == self.my_id:
                            cost = INF if c.lower()=='inf' else int(c)
                            self.neighbor_costs[b] = cost
                            self.neighbors.add(b)
                    except Exception:
                        pass

        # If we have neighbors but their server infos (IPs) are missing, we still may have them in servers map
        # Keep last_heard initial as current time for neighbors
        for n in self.neighbors:
            self.last_heard[n] = now()

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
        # Expecting JSON as per our format
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
            # if neighbor gone / reported INF to something, we won't remove entries automatically
            # but timeouts handle neighbors disappearance
            # (assignment requires not removing server from table, just set cost to infinity)
            # nothing further to do
            # We do not trigger immediate updates on change (assignment specification).
            # So only print success message of receiving is required (done above).
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
                        print(f"{cmd} SUCCESS")
                    elif b == self.my_id:
                        with LOCK:
                            self.neighbor_costs[a] = cost
                            self.neighbors.add(a)
                            self.last_heard.setdefault(a, now())
                            self.routing_table[a] = {'cost': cost, 'next_hop': a if cost < INF else -1}
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
                    # close all connections. Set all neighbor costs to INF and exit
                    with LOCK:
                        for n in list(self.neighbors):
                            self.neighbor_costs[n] = INF
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


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Distance Vector server")
    parser.add_argument('-t', dest='topo', required=True, help='topology file name')
    parser.add_argument('-i', dest='interval', required=True, help='routing update interval in seconds')
    args = parser.parse_args()

    server = DVServer(args.topo, args.interval)
    print(f"Server {server.my_id} starting on {server.my_ip}:{server.my_port} with interval {server.interval}s")
    server.start()
