import socket
import threading
import select
import json
import datetime
import time
import os
from collections import defaultdict


# Load configuration
CONFIG_FILE = 'config.json'

def load_config():
    try:
        with open(CONFIG_FILE, 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        print(f"Error: {CONFIG_FILE} not found.")
        return None

config = load_config()
if not config:
    # Fallback defaults if config fails
    config = {
        "port": 8888,
        "blocked_domains": [],
        "blocked_ips": [],

        "buffer_size": 4096,
        "max_connections": 100
    }

PORT = config.get('port', 8888)
BLOCKED_DOMAINS = set(config.get('blocked_domains', []))
BLOCKED_IPS = set(config.get('blocked_ips', []))

BUFFER_SIZE = config.get('buffer_size', 4096)
CONNECTION_HISTORY = defaultdict(list)

def get_connection_frequency(ip):
    now = time.time()
    # Auto-cleanup old entries
    CONNECTION_HISTORY[ip] = [t for t in CONNECTION_HISTORY[ip] if now - t < 60]
    CONNECTION_HISTORY[ip].append(now)
    return len(CONNECTION_HISTORY[ip])

from urllib.parse import urlparse
from uuid import uuid4

def log_activity(client_addr, url, action, details=None):
    # Extract IP from client_addr tuple (ip, port)
    client_ip = client_addr[0] if client_addr else "Unknown"
    
    # Ensure details is a dict
    if not isinstance(details, dict):
        details = {"msg": str(details)} if details else {}

    timestamp = datetime.datetime.now().strftime('%d/%m/%Y %H:%M:%S')
    ts = time.time()
    
    # Build structured log event
    log_event = {
        "ts": ts,
        "timestamp": timestamp,
        "client_ip": client_ip,
        "action": action,
        "url": url,
        "host": details.get('host', urlparse(url).netloc if '://' in url else url),
        "method": details.get('method', 'UNKNOWN'),
        "protocol": details.get('proto', 'HTTP'),
        "connected_ip": details.get('connected_ip', 'N/A'),
        "resolved_ip": details.get('resolved_ip', 'Unresolved'),
        "port": details.get('dest_port', 80),
        "bytes_up": details.get('bytes_up', 0),
        "bytes_down": details.get('bytes_down', 0),
        "duration": details.get('duration', 0),
        "freq_1m": details.get('freq', 0),
        "conn_id": details.get('conn_id', 'N/A')
    }

    if action == "BLOCKED":
        log_event["reason"] = details.get('reason', 'Unknown')
    
    # JSON String
    log_line = json.dumps(log_event)

    if VERBOSE:
        print(f"[{timestamp}] [{client_ip}] [{action}] {url}")

    # Write to file
    try:
        now = datetime.datetime.now()
        folder_name = f"logs/{now.strftime('%Y-%m-%d_%H')}"
        file_name = f"{now.strftime('%M')}.txt"
        
        if not os.path.exists(folder_name):
            os.makedirs(folder_name)
            
        full_log_path = os.path.join(folder_name, file_name)
        
        with open(full_log_path, 'a') as f:
            f.write(log_line + "\n")
            
    except Exception as e:
        print(f"Error writing to log: {e}")

def is_blocked(host):
    # Check domain blocking
    host_lower = host.lower()
    if host_lower in BLOCKED_DOMAINS:
        return True, "Domain Blocked"
    
    for domain in BLOCKED_DOMAINS:
        if host_lower.endswith("." + domain) or host_lower == domain:
            return True, "Domain Blocked"

    if host in BLOCKED_IPS:
         return True, "IP Blocked"

    return False, ""

def handle_client(client_socket, client_addr):
    conn_id = uuid4().hex
    start_time = time.time()
    
    # Track frequency at the start of connection
    client_ip = client_addr[0] if client_addr else "Unknown"
    freq = get_connection_frequency(client_ip)

    protocol = "HTTP"
    bytes_up = 0
    bytes_down = 0
    resolved_ip = "Unknown"
    connected_ip = "Not Connected"
    host = ""
    port = 80
    
    remote_socket = None
    try:
        # Set explicit timeout for client socket
        client_socket.settimeout(10.0)

        request = client_socket.recv(BUFFER_SIZE)
        if not request:
            return
        
        bytes_up += len(request) # Count initial request bytes

        first_line = request.split(b'\n')[0].strip()
        if not first_line:
            return
            
        try:
            method, url, proto_ver = first_line.split(b' ')
            method = method.decode('utf-8')
            url = url.decode('utf-8')
        except ValueError:
            return

        if method == 'CONNECT':
            protocol = "HTTPS/CONNECT"
            host_port = url.split(':')
            host = host_port[0]
            if len(host_port) > 1:
                port = int(host_port[1])
            else:
                port = 443
        else:
            protocol = "HTTP"
            if '://' in url:
                url_parts = url.split('://', 1)[1]
                host_port_path = url_parts.split('/', 1)
                host_port = host_port_path[0].split(':')
                host = host_port[0]
                if len(host_port) > 1:
                    port = int(host_port[1])
            else:
                 # Try to extract host from headers if url is relative
                 host = ""
                 for line in request.split(b'\r\n'):
                     if line.lower().startswith(b'host:'):
                         host = line.split(b':', 1)[1].strip().decode('utf-8')
                         break
                 if not host:
                     return

        # Resolve Destination IP
        try:
            resolved_ip = socket.gethostbyname(host)
        except:
            resolved_ip = "Unresolved"

        blocked, reason = is_blocked(host)
        if blocked:
            log_activity(client_addr, host, "BLOCKED", {"reason": reason, "host": host, "method": method})
            response = b"HTTP/1.1 403 Forbidden\r\nContent-Type: text/plain\r\n\r\nAccess Denied by Proxy"
            client_socket.sendall(response)
            return

        # Connect to remote server
        try:
            remote_socket = socket.create_connection((host, port), timeout=10)
            # Reset default or keep it? Keeping it safe.
            connected_ip = remote_socket.getpeername()[0]
        except Exception as e:
            # print(f"Failed to connect to {host}:{port} - {e}")
            return

        if method == 'CONNECT':
            # For HTTPS, establish tunnel
            client_socket.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            # Tunnel data
            u, d = tunnel(client_socket, remote_socket)
            bytes_up += u
            bytes_down += d
        else:
            # For HTTP, forward the original request
            remote_socket.sendall(request)
            u, d = tunnel(client_socket, remote_socket)
            bytes_up += u
            bytes_down += d

        # Calculate metrics
        duration = time.time() - start_time
        if client_addr:
            client_ip = client_addr[0]
        
        # Prepare Log URL
        log_url = host
        if method != 'CONNECT':
            if '://' in url:
                log_url = url
            else:
                log_url = f"{host}{url}"

        details = {
            "conn_id": conn_id,
            "proto": protocol,
            "resolved_ip": resolved_ip,
            "connected_ip": connected_ip,
            "dest_port": port,
            "bytes_up": bytes_up,
            "bytes_down": bytes_down,
            "duration": duration,
            "freq": freq,
            "host": host,
            "method": method
        }
        
        log_activity(client_addr, log_url, "ALLOWED", details)

    except Exception as e:
        # print(f"Error handling request: {e}")
        pass
    finally:
        # Ensure cleanup
        try:
            client_socket.close()
        except: pass
        
        if remote_socket:
            try:
                remote_socket.close()
            except: pass

def tunnel(client, remote):
    # Select loop to forward data between two sockets
    sockets = [client, remote]
    bytes_up = 0
    bytes_down = 0
    try:
        while True:
            readable, _, _ = select.select(sockets, [], [], 60)
            if not readable:
                break
            
            for s in readable:
                other = remote if s is client else client
                try:
                    data = s.recv(BUFFER_SIZE)
                    if not data:
                        return bytes_up, bytes_down # Connection closed
                    
                    if s is client:
                        bytes_up += len(data)
                    else:
                        bytes_down += len(data)
                        
                    other.sendall(data)
                except:
                    return bytes_up, bytes_down # socket error
    except:
        pass
    finally:
        client.close()
        remote.close()
    return bytes_up, bytes_down

RUNNING = True
SERVER_SOCKET = None
VERBOSE = False # Silent by default

def save_config():
    config['blocked_domains'] = list(BLOCKED_DOMAINS)
    config['blocked_ips'] = list(BLOCKED_IPS)
    try:
        with open(CONFIG_FILE, 'w') as f:
            json.dump(config, f, indent=4)
        print("[*] Configuration saved.")
    except Exception as e:
        print(f"Error saving config: {e}")

def start_proxy_thread():
    global SERVER_SOCKET
    
    # Reload config values
    current_port = config.get('port', 8888)
    current_ip = config.get('bind_ip', '127.0.0.1')
    
    SERVER_SOCKET = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    SERVER_SOCKET.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    try:
        SERVER_SOCKET.bind((current_ip, current_port))
    except PermissionError:
        print(f"Error: Permission denied binding to {current_ip}:{current_port}")
        return
    except Exception as e:
        print(f"Error binding to {current_ip}:{current_port}: {e}")
        return

    SERVER_SOCKET.listen(config.get('max_connections', 100))
    print(f"\n[*] Proxy server listening on {current_ip}:{current_port}")
    if not VERBOSE:
        print("[*] Logs are hidden. Type 'monitor' to see them.")
    print("[*] Type 'help' for available commands.\nProxy> ", end="", flush=True)

    try:
        while RUNNING:
            try:
                SERVER_SOCKET.settimeout(1.0) # Allow checking RUNNING flag
                client_sock, addr = SERVER_SOCKET.accept()
                # Handle in new thread
                thread = threading.Thread(target=handle_client, args=(client_sock, addr))
                thread.daemon = True
                thread.start()
            except socket.timeout:
                continue
            except OSError:
                break
    except Exception as e:
        if RUNNING:
            print(f"\n[!] Server error: {e}")
    finally:
        if SERVER_SOCKET:
            SERVER_SOCKET.close()

def command_console():
    global RUNNING, VERBOSE, config, BLOCKED_DOMAINS, BLOCKED_IPS, PORT
    
    print("\n--- Interactive Proxy Console ---")
    while True:
        try:
            cmd_input = input("Proxy> ").strip().split()
            if not cmd_input:
                continue
            
            cmd = cmd_input[0].lower()
            args = cmd_input[1:]

            if cmd == 'exit':
                print("Stopping proxy server...")
                RUNNING = False
                if SERVER_SOCKET:
                    SERVER_SOCKET.close()
                break
            
            elif cmd == 'help':
                print("Available commands:")
                print("  status              - Show stats and blocked lists")
                print("  monitor             - Toggle real-time log output")
                print("  block <domain/ip>   - Block a domain or IP")
                print("  unblock <domain/ip> - Unblock a domain or IP")
                print("  logs                - Open the current log folder")
                print("  setport <port>      - Change port (requires reload)")
                print("  setip <ip>          - Change bind IP (requires reload)")
                print("  reload              - Restart server with new config")
                print("  exit                - Stop server and exit")

            elif cmd == 'status':
                print(f"Listening on: {config.get('bind_ip', '127.0.0.1')}:{config.get('port', 8888)}")
                print(f"Blocked Domains ({len(BLOCKED_DOMAINS)}): {list(BLOCKED_DOMAINS)}")
                print(f"Blocked IPs ({len(BLOCKED_IPS)}): {list(BLOCKED_IPS)}")
                print(f"Monitor Mode: {'ON' if VERBOSE else 'OFF'}")

            elif cmd == 'monitor':
                VERBOSE = not VERBOSE
                print(f"Monitor Mode: {'ON' if VERBOSE else 'OFF'}")

            elif cmd == 'block':
                if not args:
                    print("Usage: block <domain_or_ip>")
                    continue
                target = args[0].lower()
                if target.replace('.', '').isdigit():
                    BLOCKED_IPS.add(target)
                else:
                    BLOCKED_DOMAINS.add(target)
                print(f"Blocked: {target}")
                save_config()

            elif cmd == 'unblock':
                if not args:
                    print("Usage: unblock <domain_or_ip>")
                    continue
                target = args[0].lower()
                if target in BLOCKED_IPS:
                    BLOCKED_IPS.remove(target)
                elif target in BLOCKED_DOMAINS:
                    BLOCKED_DOMAINS.remove(target)
                else:
                    print("Target not found.")
                    continue
                print(f"Unblocked: {target}")
                save_config()

            elif cmd == 'setport':
                if not args or not args[0].isdigit():
                    print("Usage: setport <number>")
                    continue
                config['port'] = int(args[0])
                save_config()
                print("Port updated. Type 'reload' to apply.")

            elif cmd == 'setip':
                if not args:
                    print("Usage: setip <ip>")
                    continue
                config['bind_ip'] = args[0]
                save_config()
                print("IP updated. Type 'reload' to apply.")

            elif cmd == 'reload':
                print("Reloading server...")
                # Stop current socket to break the loop
                if SERVER_SOCKET:
                    try:
                        SERVER_SOCKET.close()
                    except:
                        pass
                
                # Wait a moment for thread to cleanup (handled by loop logic)
                # Restart thread
                t = threading.Thread(target=start_proxy_thread)
                t.start()

            elif cmd == 'logs':
                try:
                    now = datetime.datetime.now()
                    folder_name = f"logs/{now.strftime('%Y-%m-%d_%H')}"
                    
                    if not os.path.exists(folder_name):
                        print(f"No logs found for this hour yet ({folder_name})")
                    else:
                        abs_path = os.path.abspath(folder_name)
                        if os.name == 'nt':
                            os.system(f'start "" "{abs_path}"')
                            print(f" Opened log folder: {folder_name}")
                        else:
                            # Linux/Mac
                            print(f"Log directory: {abs_path}")
                            print("Tip: Use 'ls -l' or 'tail' to view files.")
                except Exception as e:
                    print(f"Error opening logs: {e}")

            else:
                print("Unknown command. Type 'help' for list.")

        except KeyboardInterrupt:
            print("\nType 'exit' to stop.")
        except Exception as e:
            print(f"Error processing command: {e}")

if __name__ == '__main__':
    # Start proxy in background thread
    t = threading.Thread(target=start_proxy_thread)
    t.start()
    
    # Run console in main thread
    command_console()
    
    # Wait for proxy thread to finish
    t.join()
