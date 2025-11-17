import nmap
import ipaddress

try:
    nm = nmap.PortScanner()
except nmap.PortScannerError as e:
    print(f"Error: {e}")
    print("Please install nmap from https://nmap.org/download.html")
    exit(1)


print("Welcome to EZMAP!")
print("Made by Ali Fatimi - Symkarian")

target = input("Enter the target IP address: ")
port_start = int(input("Enter the start port: "))
port_end = int(input("Enter the end port: "))

print("What type of scan would you like to perform?")
print("1. Full Scan")
print("2. Fast Scan")
print("3. SYN Scan")
print("4. Ping Scan")
print("5. OS Detection")
print("6. Version Detection")
print("7. All Ports Scan")
print("8. Stealth Scan with custom packet size:")
choice = input("Enter the number of the scan you would like to perform: ")
if choice == "1":
    print("Performing Full Scan...")
    nm.scan(target, str(port_start) + "-" + str(port_end), "-v -sS")
elif choice == "2":
    print("Performing Fast Scan...")
    nm.scan(target, str(port_start) + "-" + str(port_end), "-v -sF")
elif choice == "3":
    print("Performing SYN Scan...")
    nm.scan(target, str(port_start) + "-" + str(port_end), "-v -sS")
elif choice == "4":
    print("Performing Ping Scan...")
    nm.scan(target, str(port_start) + "-" + str(port_end), "-v -sP")
elif choice == "5":
    print("Performing OS Detection...")
    nm.scan(target, str(port_start) + "-" + str(port_end), "-v -sO")
elif choice == "6":
    print("Performing Version Detection...")
    nm.scan(target, str(port_start) + "-" + str(port_end), "-v -sV")
elif choice == "7":
    print("Performing All Ports Scan...")
    nm.scan(target, str(port_start) + "-" + str(port_end), "-v -sS")
elif choice == "8":
    print("Performing Stealth Scan with custom packet size...")
    packet_size = int(input("Enter the packet size: "))
    nm.scan(target, str(port_start) + "-" + str(port_end), "-v -sS -p " + str(packet_size))
else:
    print("Invalid input")
    exit(1)

# Pretty print scan results
print("\n" + "="*70)
print("SCAN RESULTS")
print("="*70)

if nm.all_hosts():
    for host in nm.all_hosts():
        print(f"\nHost: {host}")
        print("-" * 70)
        
        # Host info
        hostname = nm[host].hostname()
        state = nm[host].state()
        print(f"Hostname: {hostname if hostname else 'N/A'}")
        print(f"State: {state}")
        
        # Protocol and port information
        protocols = nm[host].all_protocols()
        if protocols:
            for protocol in protocols:
                ports = sorted(nm[host][protocol].keys())
                print(f"\nProtocol: {protocol.upper()}")
                print(f"Open Ports: {len(ports)}")
                print("-" * 70)
                print(f"{'Port':<10} {'State':<10} {'Service':<20} {'Version':<30}")
                print("-" * 70)
                
                for port in ports:
                    port_info = nm[host][protocol][port]
                    state = port_info['state']
                    service = port_info.get('name', 'unknown')
                    version = port_info.get('product', '')
                    if port_info.get('version'):
                        version += ' ' + port_info.get('version', '')
                    if port_info.get('extrainfo'):
                        version += ' ' + port_info.get('extrainfo', '')
                    version = version.strip() or 'N/A'
                    
                    print(f"{port:<10} {state:<10} {service:<20} {version:<30}")
        else:
            print("\nNo open ports found")
else:
    print("\nNo hosts found or scan did not complete successfully")

print("\n" + "="*70)
print("Scan completed!")
print("="*70)