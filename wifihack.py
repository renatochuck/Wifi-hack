import time
import random
import os
import sys
import socket
import threading
from colorama import Fore, Style, init
from datetime import datetime

init(autoreset=True)

# Enhanced version with more capabilities
VERSION = "2.0"
AUTHOR = "@renatochuck"

# Global variables
attack_log = []
session_id = random.randint(1000, 9999)
is_monitor_mode = False
is_root = True  # Simulating root privileges

def clear():
    os.system('cls' if os.name == 'nt' else 'clear')

class Spinner:
    def __init__(self):
        self.spinner = spinning_cursor()
        self.active = False
        self.spinner_thread = None

    def spinning_cursor(self):
        while True:
            for cursor in '|/-\\':
                yield cursor

    def start(self, message=""):
        self.active = True
        def spin():
            while self.active:
                sys.stdout.write(next(self.spinner) + ' ' + message)
                sys.stdout.flush()
                time.sleep(0.1)
                sys.stdout.write('\r')
        self.spinner_thread = threading.Thread(target=spin)
        self.spinner_thread.start()

    def stop(self):
        self.active = False
        if self.spinner_thread:
            self.spinner_thread.join()
        sys.stdout.write(' ' * 50 + '\r')
        sys.stdout.flush()

spinner = Spinner()

def log_attack(action, target=None, success=True, details=""):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    entry = {
        "timestamp": timestamp,
        "session": session_id,
        "action": action,
        "target": target,
        "success": success,
        "details": details
    }
    attack_log.append(entry)
    return entry

def banner():
    print(Fore.GREEN + Style.BRIGHT + f"""
⠀⠀⢀⣀⣀⣀⣀⣀⣀⣀⣀⠀⠀⠀⠀
⠀⠀⢀⣴⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⣦⡀⠀
⠀⣰⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣆
⢸⣿⣿⣿⣿⡿⠛⠉⠉⠉⠉⠛⢿⣿⣿⣿⣿⡇
⠈⠉⠉⠉⠉⠀⠀⠀⠀⠀⠀⠀⠀⠉⠉⠉⠁

   ▄▄ ▄▄▄ ▄▄▄ ▄▄▄ ▄▄▄ ▄▄
 ▄██████████████████████▄
▄██████████████████████████▄
████████████████████████████
 ▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀

   Wi-Fi Attack Tool v{VERSION}
      Author: {AUTHOR}
    For Ethical Learning Only!
""")

wifi_networks = [
    "Renato_Home_5G",
    "Free_WiFi_24G",
    "Guest_Café",
    "School_AP",
    "Hidden_Network",
    "Corporate_WLAN",
    "IoT_Network",
    "Public_Hotspot",
    "Secure_Enterprise",
    "Starbucks_WiFi"
]

vendors = ["Cisco", "Netgear", "TP-Link", "D-Link", "ASUS", "Linksys", "Ubiquiti", "MikroTik", "Aruba", "Ruckus"]

client_devices = [
    "John's iPhone", "Office-Laptop", "Android-XYZ", "Gaming-PC", 
    "SmartTV", "Tablet-001", "Security-Camera", "IoT-Device", 
    "Guest-Smartphone", "Employee-PC", "IT-Admin", "CEO-Laptop"
]

security_types = [
    "WPA2-PSK", "WPA3-SAE", "WPA2-Enterprise", "WEP", "Open",
    "WPA2/WPA3-Transition", "WPA2-CCMP", "WPA2-TKIP"
]

def random_mac():
    return ":".join(f"{random.randint(0, 255):02x}" for _ in range(6))

def random_ip():
    return f"192.168.{random.randint(1, 254)}.{random.randint(1, 254)}"

def random_bssid():
    oui = random.choice(["00:1a:2b", "a4:56:03", "d8:fe:e3", "00:0c:42"])
    return f"{oui}:{random.randint(0, 255):02x}:{random.randint(0, 255):02x}:{random.randint(0, 255):02x}"

def print_with_spinner(text, duration=2):
    spinner.start(text)
    time.sleep(duration)
    spinner.stop()
    print(f"{text} ✔")

def check_root():
    if not is_root:
        print(Fore.RED + "\n[!] Error: This tool requires root privileges!")
        print(Fore.YELLOW + "Please run as root or with sudo.\n")
        time.sleep(2)
        return False
    return True

def check_monitor_mode():
    if not is_monitor_mode:
        print(Fore.YELLOW + "\n[!] Warning: Monitor mode not enabled")
        print("Some features may not work properly\n")
        time.sleep(1)
        return False
    return True

def enable_monitor_mode():
    global is_monitor_mode
    clear()
    banner()
    print(Fore.CYAN + "\n[~] Enabling Monitor Mode...\n")
    
    print_with_spinner("Checking wireless interfaces")
    interfaces = ["wlan0", "wlan1", "wlp2s0"]
    selected_iface = random.choice(interfaces)
    
    print_with_spinner(f"Configuring {selected_iface}")
    print_with_spinner("Setting monitor mode")
    
    is_monitor_mode = True
    log_attack("Monitor Mode Enabled", selected_iface)
    
    print(Fore.GREEN + f"\n[✔] Monitor mode enabled on {selected_iface}\n")
    input(Fore.CYAN + "Press Enter to continue...")

def main_menu():
    while True:
        clear()
        banner()
        print(Fore.CYAN + f"\nSession ID: {session_id}")
        print(f"Monitor Mode: {'Enabled' if is_monitor_mode else 'Disabled'}")
        print(f"Root Access: {'Yes' if is_root else 'No'}\n")
        
        print(Fore.CYAN + "[1] Scan Nearby Wi-Fi")
        print("[2] Attack Tools")
        print("[3] Extra Features")
        print("[4] System Configuration")
        print("[5] View Attack Log")
        print("[6] Exit")
        
        choice = input(Fore.YELLOW + "\nSelect Option: ")
        
        if choice == "1":
            scan_wifi()
        elif choice == "2":
            if check_root():
                attack_tools_menu()
        elif choice == "3":
            extra_features_menu()
        elif choice == "4":
            system_config_menu()
        elif choice == "5":
            view_attack_log()
        elif choice == "6":
            print(Fore.RED + "\nExiting... Stay safe!\n")
            time.sleep(1)
            break
        else:
            print(Fore.RED + "Invalid input. Try again.")
            time.sleep(1)

def scan_wifi():
    clear()
    banner()
    print(Fore.CYAN + "\n[+] Scanning for Wi-Fi Networks...\n")
    
    print_with_spinner("Initializing scan")
    print_with_spinner("Capturing beacon frames", 3)
    
    print(Fore.YELLOW + "\n[+] Nearby Wi-Fi Networks:\n")
    
    # Generate random networks with more details
    for idx in range(random.randint(5, 15)):
        ssid = random.choice(wifi_networks) if random.random() > 0.3 else f"Hidden_Network_{random.randint(100,999)}"
        signal = random.randint(20, 99)
        channel = random.choice([1, 6, 11, 36, 40, 44, 48, 149, 153, 157, 161])
        security = random.choice(security_types)
        bssid = random_bssid()
        
        print(Fore.GREEN + f"[{idx+1}] {ssid}")
        print(Fore.CYAN + f"    Signal: {signal}% | Channel: {channel} | Security: {security}")
        print(Fore.MAGENTA + f"    BSSID: {bssid} | Clients: {random.randint(0, 8)}")
        print()
        time.sleep(0.2)
    
    selected = input(Fore.YELLOW + "\nSelect Wi-Fi Name or Number (or Enter to go back): ")
    if not selected:
        return
    
    try:
        if selected.isdigit():
            idx = int(selected) - 1
            if 0 <= idx < len(wifi_networks):
                target = wifi_networks[idx]
            else:
                print(Fore.RED + "\nInvalid selection.")
                time.sleep(1)
                return
        else:
            target = selected
        
        wifi_options(target)
    except ValueError:
        print(Fore.RED + "\nInvalid input.")
        time.sleep(1)

def wifi_options(target):
    clear()
    banner()
    print(Fore.CYAN + f"\n[~] Analyzing '{target}'...\n")
    
    print_with_spinner("Capturing packets", 2)
    print_with_spinner("Analyzing traffic", 2)
    
    mac = random_bssid()
    channel = random.choice([1, 6, 11])
    vendor = random.choice(vendors)
    security = random.choice(security_types)
    clients = random.sample(client_devices, random.randint(1, 5))
    
    print(Fore.GREEN + f"[✔] Target: {target}")
    print(Fore.MAGENTA + f"[!] Security: {security} | Clients: {len(clients)}")
    print(Fore.CYAN + f"    BSSID: {mac} | Channel: {channel} | Vendor: {vendor}")
    print(Fore.CYAN + f"    First Seen: {random.randint(1, 24)} hours ago")
    print(Fore.CYAN + f"    Data Rate: {random.choice(['54 Mbps', '150 Mbps', '300 Mbps', '450 Mbps', '867 Mbps'])}\n")
    
    print(Fore.YELLOW + "Connected Clients:")
    for i, c in enumerate(clients, 1):
        print(Fore.CYAN + f" - {c} [{random_mac()}] | IP: {random_ip()} | Signal: {random.randint(30, 90)}%")
    
    while True:
        print(Fore.YELLOW + f"\nAttack Options for '{target}':")
        print("[1] Crack Password")
        print("[2] Deauth Attack")
        print("[3] Evil Twin Attack")
        print("[4] WPS PIN Attack")
        print("[5] WPA Enterprise Attack")
        print("[6] Return to Main Menu")
        
        opt = input(Fore.CYAN + "\nSelect Option: ")
        
        if opt == "1":
            crack_password(target, clients)
        elif opt == "2":
            deauth_attack(target, clients)
        elif opt == "3":
            evil_twin_attack(target, clients)
        elif opt == "4":
            wps_attack(target)
        elif opt == "5":
            wpa_enterprise_attack(target)
        elif opt == "6":
            break
        else:
            print(Fore.RED + "Invalid choice.\n")

def crack_password(target, clients):
    if not check_monitor_mode():
        return
    
    clear()
    banner()
    print(Fore.YELLOW + f"\n[~] Starting password cracking on {target}...\n")
    
    print_with_spinner("Capturing handshake", 3)
    print_with_spinner("Analyzing encryption", 2)
    
    wordlists = [
        "rockyou.txt", "darkweb2017.txt", 
        "custom_wordlist.txt", "passwords.lst"
    ]
    
    selected_wordlist = random.choice(wordlists)
    print(Fore.CYAN + f"\nUsing wordlist: {selected_wordlist}")
    
    fake_passwords = [
        "password123", "admin1234", "letmein", "12345678", 
        "qwerty2025", "freewifi", "hacker2025", target.lower(),
        f"{target}123", "welcome1", "securepass", "P@ssw0rd"
    ]
    
    attempts = random.randint(8, 15)
    for attempt in range(1, attempts + 1):
        pwd_try = random.choice(fake_passwords) + str(random.randint(0, 99))
        print(Fore.MAGENTA + f"[*] Attempt {attempt}/{attempts}: {pwd_try}")
        time.sleep(0.3 + random.random() * 0.5)
    
    if random.random() > 0.2:  # 80% success rate
        cracked_pass = f"{target}_@hack{random.randint(1000, 9999)}"
        print(Fore.GREEN + f"\n[✔] Password Cracked: {cracked_pass}")
        log_attack("Password Crack", target, True, f"Password: {cracked_pass}")
        
        # Save to file
        with open(f"cracked_{target}.txt", "w") as f:
            f.write(f"SSID: {target}\nPassword: {cracked_pass}\n")
        print(Fore.CYAN + f"Saved to: cracked_{target}.txt\n")
    else:
        print(Fore.RED + "\n[✖] Failed to crack password")
        print(Fore.YELLOW + "Try with a larger wordlist or different attack method")
        log_attack("Password Crack", target, False, "Failed after attempts")
    
    input(Fore.CYAN + "\nPress Enter to return...")

def deauth_attack(target, clients):
    if not check_monitor_mode():
        return
    
    clear()
    banner()
    print(Fore.YELLOW + f"\n[~] Preparing deauthentication attack on {target}...\n")
    
    duration = input(Fore.CYAN + "Attack duration (seconds, default 10): ") or "10"
    try:
        duration = int(duration)
    except ValueError:
        duration = 10
    
    print_with_spinner("Setting up packet injection", 2)
    
    target_mac = random_bssid()
    print(Fore.CYAN + f"\nTarget BSSID: {target_mac}")
    
    # Select clients to target
    print(Fore.YELLOW + "\nSelect clients to target:")
    print("[1] All clients")
    print("[2] Specific client")
    choice = input(Fore.CYAN + "Choice (1/2): ")
    
    if choice == "1":
        print(Fore.RED + f"\n[!] Sending deauth packets to all clients on {target}...")
        for i in range(duration * 2):  # 2 packets per second
            for client in clients:
                print(Fore.MAGENTA + f"[*] Sent deauth to {client} [{random_mac()}]")
                time.sleep(0.1)
            time.sleep(0.4)
    elif choice == "2":
        print(Fore.YELLOW + "\nAvailable clients:")
        for i, client in enumerate(clients, 1):
            print(f"[{i}] {client} [{random_mac()}]")
        
        selected = input(Fore.CYAN + "Select client number: ")
        try:
            idx = int(selected) - 1
            if 0 <= idx < len(clients):
                target_client = clients[idx]
                print(Fore.RED + f"\n[!] Targeting client: {target_client}")
                
                for i in range(duration * 5):  # 5 packets per second
                    print(Fore.MAGENTA + f"[*] Sent deauth to {target_client}")
                    time.sleep(0.05)
            else:
                print(Fore.RED + "Invalid selection")
                time.sleep(1)
                return
        except ValueError:
            print(Fore.RED + "Invalid input")
            time.sleep(1)
            return
    
    print(Fore.GREEN + f"\n[✔] Deauth attack completed on {target}")
    log_attack("Deauth Attack", target, True, f"Duration: {duration}s")
    
    input(Fore.CYAN + "\nPress Enter to return...")

def evil_twin_attack(target, clients):
    if not check_root():
        return
    
    clear()
    banner()
    print(Fore.YELLOW + f"\n[~] Setting up Evil Twin for {target}...\n")
    
    print_with_spinner("Configuring rogue AP", 2)
    print_with_spinner("Setting up DHCP server", 2)
    print_with_spinner("Preparing phishing page", 2)
    
    fake_ssid = f"{target}_FREE"
    print(Fore.GREEN + f"\n[✔] Evil Twin AP created: {fake_ssid}")
    print(Fore.CYAN + f"    Channel: {random.choice([1, 6, 11])}")
    print(Fore.CYAN + f"    IP Range: 192.168.{random.randint(1, 254)}.1/24")
    
    # Simulate clients connecting
    print(Fore.YELLOW + "\nWaiting for clients to connect...")
    connected_clients = random.sample(clients, random.randint(1, min(5, len(clients))))
    
    for client in connected_clients:
        print_with_spinner(f"Client {client} connecting", 1)
        print(Fore.MAGENTA + f"[*] {client} connected | IP: {random_ip()}")
        time.sleep(0.5)
    
    # Simulate credential capture
    if connected_clients and random.random() > 0.3:
        print(Fore.RED + "\n[!] Captured credentials:")
        fake_users = ["admin", "user123", "john.doe", "company_user", "guest"]
        fake_passwords = ["password", "123456", "welcome", "letmein", "P@ssw0rd"]
        
        for i in range(random.randint(1, 3)):
            user = random.choice(fake_users)
            pwd = random.choice(fake_passwords)
            print(Fore.RED + f" - Username: {user} | Password: {pwd}")
            log_attack("Credential Capture", target, True, f"{user}:{pwd}")
            time.sleep(0.5)
        
        print(Fore.GREEN + "\n[✔] Credentials saved to captured_logins.txt")
    
    print(Fore.YELLOW + "\n[!] Press Ctrl+C to stop Evil Twin")
    input(Fore.CYAN + "\nPress Enter to simulate stopping attack...")
    
    print(Fore.GREEN + "\n[✔] Evil Twin attack completed")
    log_attack("Evil Twin Attack", target, True, f"SSID: {fake_ssid}")
    
    input(Fore.CYAN + "\nPress Enter to return...")

def wps_attack(target):
    if not check_monitor_mode():
        return
    
    clear()
    banner()
    print(Fore.YELLOW + f"\n[~] Starting WPS PIN attack on {target}...\n")
    
    print_with_spinner("Checking WPS support", 2)
    
    if random.random() > 0.7:
        print(Fore.RED + "\n[✖] Target doesn't support WPS")
        log_attack("WPS Attack", target, False, "WPS not supported")
        input(Fore.CYAN + "\nPress Enter to return...")
        return
    
    print(Fore.GREEN + "[✔] WPS enabled on target")
    print(Fore.CYAN + "\nStarting PIN brute-force...")
    
    pins = [12345678, 11112222, 87654321, 11223344, 33445566]
    for i, pin in enumerate(pins, 1):
        print(Fore.MAGENTA + f"[*] Trying PIN: {pin}")
        time.sleep(0.5)
    
    if random.random() > 0.3:
        cracked_pin = random.choice(pins)
        print(Fore.GREEN + f"\n[✔] WPS PIN Found: {cracked_pin}")
        print(Fore.CYAN + f"Network Password: {target.lower()}_{cracked_pin}")
        log_attack("WPS Attack", target, True, f"PIN: {cracked_pin}")
    else:
        print(Fore.RED + "\n[✖] Failed to crack WPS PIN")
        print(Fore.YELLOW + "Target may have WPS locked")
        log_attack("WPS Attack", target, False, "Failed after attempts")
    
    input(Fore.CYAN + "\nPress Enter to return...")

def wpa_enterprise_attack(target):
    if not check_root():
        return
    
    clear()
    banner()
    print(Fore.YELLOW + f"\n[~] Preparing WPA Enterprise attack on {target}...\n")
    
    print_with_spinner("Detecting EAP method", 2)
    eap_method = random.choice(["PEAP", "EAP-TTLS", "EAP-TLS"])
    print(Fore.CYAN + f"\nDetected EAP method: {eap_method}")
    
    print_with_spinner("Creating fake RADIUS server", 3)
    
    print(Fore.YELLOW + "\nSelect attack method:")
    print("[1] Credential phishing")
    print("[2] Certificate spoofing")
    choice = input(Fore.CYAN + "Choice (1/2): ")
    
    if choice == "1":
        print(Fore.RED + "\n[!] Starting credential phishing attack...")
        print_with_spinner("Setting up fake login page", 2)
        
        # Simulate captured credentials
        domains = ["company.com", "university.edu", "corp.net"]
        fake_users = ["j.smith", "m.johnson", "admin", "it.support"]
        
        for i in range(random.randint(1, 3)):
            user = random.choice(fake_users)
            domain = random.choice(domains)
            password = f"Spring{random.randint(2020, 2024)}!"
            print(Fore.RED + f"[!] Captured: {user}@{domain} : {password}")
            log_attack("Enterprise Cred Capture", target, True, f"{user}@{domain}:{password}")
            time.sleep(1)
        
        print(Fore.GREEN + "\n[✔] Credentials captured")
    elif choice == "2":
        print(Fore.RED + "\n[!] Attempting certificate spoofing...")
        print_with_spinner("Generating fake certificate", 3)
        
        if random.random() > 0.5:
            print(Fore.GREEN + "\n[✔] Certificate accepted by client")
            print(Fore.CYAN + "Now intercepting encrypted traffic...")
            log_attack("Enterprise Cert Spoof", target, True, "Successful MITM")
        else:
            print(Fore.RED + "\n[✖] Certificate rejected")
            print(Fore.YELLOW + "Target may have certificate pinning")
            log_attack("Enterprise Cert Spoof", target, False, "Certificate rejected")
    else:
        print(Fore.RED + "Invalid choice")
        time.sleep(1)
        return
    
    input(Fore.CYAN + "\nPress Enter to return...")

def attack_tools_menu():
    while True:
        clear()
        banner()
        print(Fore.CYAN + "\nAdvanced Attack Tools:\n")
        
        print("[1] Automated Wi-Fi Cracker")
        print("[2] Persistent Evil Twin")
        print("[3] Wi-Fi Jamming Tool")
        print("[4] Client Probe Sniffer")
        print("[5] Return to Main Menu")
        
        choice = input(Fore.YELLOW + "\nSelect Option: ")
        
        if choice == "1":
            automated_cracker()
        elif choice == "2":
            persistent_evil_twin()
        elif choice == "3":
            wifi_jammer()
        elif choice == "4":
            probe_sniffer()
        elif choice == "5":
            break
        else:
            print(Fore.RED + "Invalid choice")
            time.sleep(1)

def automated_cracker():
    clear()
    banner()
    print(Fore.YELLOW + "\n[~] Starting Automated Wi-Fi Cracker...\n")
    
    print_with_spinner("Scanning for vulnerable networks", 3)
    
    # Generate fake vulnerable networks
    vulnerable_nets = []
    for i in range(random.randint(1, 4)):
        ssid = random.choice(wifi_networks)
        reason = random.choice([
            "Weak WPS implementation",
            "WPA2 with weak password",
            "WEP encryption detected",
            "Open network with client data"
        ])
        vulnerable_nets.append((ssid, reason))
    
    if not vulnerable_nets:
        print(Fore.RED + "\n[✖] No vulnerable networks found")
        input(Fore.CYAN + "\nPress Enter to return...")
        return
    
    print(Fore.YELLOW + "\n[!] Vulnerable Networks Found:")
    for i, (ssid, reason) in enumerate(vulnerable_nets, 1):
        print(Fore.RED + f"[{i}] {ssid} - {reason}")
    
    print(Fore.CYAN + "\nStarting automated attacks...")
    
    for ssid, reason in vulnerable_nets:
        print(Fore.YELLOW + f"\nAttacking: {ssid} ({reason})")
        
        if "WPS" in reason:
            wps_attack(ssid)
        elif "WEP" in reason:
            wep_attack(ssid)
        elif "weak password" in reason:
            clients = random.sample(client_devices, random.randint(1, 3))
            crack_password(ssid, clients)
        elif "Open network" in reason:
            open_network_attack(ssid)
        
        time.sleep(1)
    
    print(Fore.GREEN + "\n[✔] Automated attacks completed")
    input(Fore.CYAN + "\nPress Enter to return...")

def wep_attack(target):
    print_with_spinner("Collecting IVs", 4)
    
    ivs_collected = random.randint(5000, 15000)
    print(Fore.CYAN + f"\nCollected {ivs_collected} IVs")
    
    print_with_spinner("Cracking with aircrack-ng", 3)
    
    if random.random() > 0.2:
        key = ":".join(f"{random.randint(0, 255):02x}" for _ in range(5))
        print(Fore.GREEN + f"\n[✔] WEP Key Cracked: {key}")
        log_attack("WEP Crack", target, True, f"Key: {key}")
    else:
        print(Fore.RED + "\n[✖] Failed to crack WEP key")
        print(Fore.YELLOW + "Need more IVs for successful crack")
        log_attack("WEP Crack", target, False, "Insufficient IVs")

def open_network_attack(target):
    print_with_spinner("Sniffing traffic", 3)
    
    if random.random() > 0.5:
        print(Fore.RED + "\n[!] Captured plaintext data:")
        data_types = [
            "HTTP login: user=admin&pass=password123",
            "Email: john@example.com | Subject: Confidential",
            "FTP credentials: ftpuser:ftppass",
            "Cookies: sessionid=ABCDEF123456"
        ]
        
        for i in range(random.randint(1, 3)):
            print(Fore.RED + f" - {random.choice(data_types)}")
            time.sleep(0.5)
        
        print(Fore.GREEN + "\n[✔] Data captured from open network")
        log_attack("Open Network Sniff", target, True, "Captured plaintext data")
    else:
        print(Fore.YELLOW + "\n[!] No interesting data captured")
        log_attack("Open Network Sniff", target, False, "No valuable data")

def persistent_evil_twin():
    clear()
    banner()
    print(Fore.YELLOW + "\n[~] Persistent Evil Twin Attack...\n")
    
    print(Fore.RED + "[!] WARNING: This attack will run continuously")
    print(Fore.RED + "             until manually stopped\n")
    
    target = input(Fore.CYAN + "Enter target SSID to clone: ")
    if not target:
        return
    
    duration = input(Fore.CYAN + "Duration (minutes, 0=indefinite): ")
    try:
        duration = int(duration) if duration else 0
    except ValueError:
        duration = 0
    
    print_with_spinner("Setting up persistent AP", 3)
    print_with_spinner("Configuring auto-restart", 2)
    
    print(Fore.GREEN + f"\n[✔] Persistent Evil Twin running for {target}")
    print(Fore.YELLOW + "[!] Press Ctrl+C to stop the attack\n")
    
    # Simulate running attack
    start_time = time.time()
    try:
        while duration == 0 or (time.time() - start_time) < duration * 60:
            clients = random.sample(client_devices, random.randint(0, 3))
            for client in clients:
                print(Fore.MAGENTA + f"[*] {client} connected to fake AP")
                time.sleep(1)
            
            if random.random() > 0.7 and clients:
                cred = random.choice(["admin:password", "user:123456", "guest:welcome"])
                print(Fore.RED + f"[!] Captured credentials: {cred}")
                log_attack("Persistent Evil Twin", target, True, f"Cred: {cred}")
            
            time.sleep(3)
    except KeyboardInterrupt:
        pass
    
    print(Fore.GREEN + "\n[✔] Stopped persistent attack")
    log_attack("Persistent Evil Twin", target, True, f"Duration: {duration} min")
    
    input(Fore.CYAN + "\nPress Enter to return...")

def wifi_jammer():
    if not check_monitor_mode():
        return
    
    clear()
    banner()
    print(Fore.YELLOW + "\n[~] Wi-Fi Jamming Tool...\n")
    
    print(Fore.RED + "[!] WARNING: This may disrupt all nearby Wi-Fi networks")
    print(Fore.RED + "             Use only for authorized testing\n")
    
    print(Fore.CYAN + "Select jamming mode:")
    print("[1] Target specific channel")
    print("[2] Sweep all channels")
    print("[3] Return")
    
    choice = input(Fore.YELLOW + "\nChoice (1/2/3): ")
    
    if choice == "3":
        return
    
    if choice == "1":
        channel = input(Fore.CYAN + "Enter channel (1-14, 36-165): ")
        try:
            channel = int(channel)
            if not (1 <= channel <= 14 or 36 <= channel <= 165):
                raise ValueError
        except ValueError:
            print(Fore.RED + "Invalid channel")
            time.sleep(1)
            return
        
        print(Fore.RED + f"\n[!] Jamming channel {channel}...")
        print(Fore.YELLOW + "[!] Press Ctrl+C to stop\n")
        
        try:
            while True:
                print(Fore.MAGENTA + f"[*] Sending continuous jamming packets on channel {channel}")
                time.sleep(0.5)
        except KeyboardInterrupt:
            print(Fore.GREEN + "\n[✔] Stopped jamming")
    
    elif choice == "2":
        duration = input(Fore.CYAN + "Enter sweep duration (seconds): ")
        try:
            duration = int(duration)
        except ValueError:
            print(Fore.RED + "Invalid duration")
            time.sleep(1)
            return
        
        print(Fore.RED + f"\n[!] Sweeping all channels for {duration} seconds...")
        print(Fore.YELLOW + "[!] Press Ctrl+C to stop\n")
        
        channels = [1,6,11,36,40,44,48,149,153,157,161,165]
        start_time = time.time()
        
        try:
            while (time.time() - start_time) < duration:
                for channel in channels:
                    print(Fore.MAGENTA + f"[*] Jamming channel {channel}")
                    time.sleep(0.3)
        except KeyboardInterrupt:
            pass
        
        print(Fore.GREEN + "\n[✔] Sweep completed")
    
    log_attack("Wi-Fi Jamming", "Multiple", True, f"Mode: {choice}")
    input(Fore.CYAN + "\nPress Enter to return...")

def probe_sniffer():
    if not check_monitor_mode():
        return
    
    clear()
    banner()
    print(Fore.YELLOW + "\n[~] Client Probe Sniffer...\n")
    
    print_with_spinner("Capturing probe requests", 3)
    
    print(Fore.CYAN + "\nDetected Client Probes:\n")
    
    devices = [
        ("iPhone", "Apple"),
        ("Galaxy S23", "Samsung"),
        ("Windows Laptop", "Microsoft"),
        ("Android TV", "Google"),
        ("iPad", "Apple")
    ]
    
    for i in range(random.randint(5, 15)):
        device, vendor = random.choice(devices)
        mac = random_mac()
        ssid = random.choice(wifi_networks + ["Hidden_SSID"])
        
        print(Fore.GREEN + f"[{i+1}] {device} [{mac}]")
        print(Fore.CYAN + f"    Vendor: {vendor}")
        print(Fore.MAGENTA + f"    Looking for: {ssid}")
        print(Fore.YELLOW + f"    Signal: {random.randint(30, 90)}% | Channel: {random.choice([1,6,11])}\n")
        time.sleep(0.3)
    
    print(Fore.GREEN + "\n[✔] Probe capture completed")
    log_attack("Probe Sniffing", "Multiple", True, "Captured client probes")
    
    input(Fore.CYAN + "\nPress Enter to return...")

def system_config_menu():
    while True:
        clear()
        banner()
        print(Fore.CYAN + "\nSystem Configuration:\n")
        
        print(f"[1] {'Disable' if is_monitor_mode else 'Enable'} Monitor Mode")
        print("[2] Change Wireless Channel")
        print("[3] Check System Dependencies")
        print("[4] Return to Main Menu")
        
        choice = input(Fore.YELLOW + "\nSelect Option: ")
        
        if choice == "1":
            if is_monitor_mode:
                global is_monitor_mode
                is_monitor_mode = False
                print(Fore.GREEN + "\n[✔] Monitor mode disabled")
            else:
                enable_monitor_mode()
            time.sleep(1)
        elif choice == "2":
            change_channel()
        elif choice == "3":
            check_dependencies()
        elif choice == "4":
            break
        else:
            print(Fore.RED + "Invalid choice")
            time.sleep(1)

def change_channel():
    clear()
    banner()
    print(Fore.CYAN + "\n[~] Changing Wireless Channel...\n")
    
    channel = input(Fore.YELLOW + "Enter channel (1-14, 36-165): ")
    try:
        channel = int(channel)
        if not (1 <= channel <= 14 or 36 <= channel <= 165):
            raise ValueError
        
        print_with_spinner(f"Setting channel to {channel}", 2)
        print(Fore.GREEN + f"\n[✔] Channel changed to {channel}")
        log_attack("Channel Change", "Interface", True, f"Channel: {channel}")
    except ValueError:
        print(Fore.RED + "\nInvalid channel number")
    
    input(Fore.CYAN + "\nPress Enter to return...")

def check_dependencies():
    clear()
    banner()
    print(Fore.CYAN + "\n[~] Checking System Dependencies...\n")
    
    tools = [
        ("aircrack-ng", True),
        ("iwconfig", True),
        ("macchanger", random.random() > 0.2),
        ("hostapd", True),
        ("dnsmasq", True),
        ("reaver", random.random() > 0.3),
        ("bully", random.random() > 0.7)
    ]
    
    for tool, available in tools:
        if available:
            print(Fore.GREEN + f"[✔] {tool.ljust(12)} Installed")
        else:
            print(Fore.RED + f"[✖] {tool.ljust(12)} Not found")
        time.sleep(0.2)
    
    if all(avail for _, avail in tools):
        print(Fore.GREEN + "\nAll dependencies are satisfied")
    else:
        print(Fore.YELLOW + "\nSome tools are missing - certain features may not work")
    
    input(Fore.CYAN + "\nPress Enter to return...")

def view_attack_log():
    clear()
    banner()
    print(Fore.CYAN + f"\nAttack Log - Session {session_id}\n")
    
    if not attack_log:
        print(Fore.YELLOW + "No logged activities yet")
        input(Fore.CYAN + "\nPress Enter to return...")
        return
    
    for entry in attack_log[-20:]:  # Show last 20 entries
        color = Fore.GREEN if entry["success"] else Fore.RED
        print(f"{color}[{entry['timestamp']}] {entry['action']}")
        print(Fore.CYAN + f"   Target: {entry['target'] or 'N/A'}")
        if entry["details"]:
            print(Fore.YELLOW + f"   Details: {entry['details']}")
        print()
    
    print(Fore.CYAN + f"\nTotal logged activities: {len(attack_log)}")
    
    # Save log option
    save = input(Fore.YELLOW + "\nSave log to file? (y/N): ").lower()
    if save == 'y':
        filename = f"attack_log_{session_id}.txt"
        with open(filename, 'w') as f:
            f.write(f"Attack Log - Session {session_id}\n\n")
            for entry in attack_log:
                f.write(f"[{entry['timestamp']}] {entry['action']}\n")
                f.write(f"   Target: {entry['target'] or 'N/A'}\n")
                if entry["details"]:
                    f.write(f"   Details: {entry['details']}\n")
                f.write("\n")
        print(Fore.GREEN + f"\nLog saved to {filename}")
    
    input(Fore.CYAN + "\nPress Enter to return...")

def extra_features_menu():
    total_features = 100  # Increased to 100 features
    
    while True:
        clear()
        banner()
        print(Fore.CYAN + f"\nExtra Features Menu (100 Simulations):\n")
        
        print("[1-20] Basic Wi-Fi Tools")
        print("[21-40] Advanced Attacks")
        print("[41-60] Network Analysis")
        print("[61-80] Security Testing")
        print("[81-100] Miscellaneous")
        print("[0] Back to Main Menu")
        
        choice = input(Fore.GREEN + "\nSelect Feature Number (or range like 20-30): ")
        
        if choice == "0":
            break
        elif "-" in choice:
            try:
                start, end = map(int, choice.split("-"))
                if 1 <= start <= end <= total_features:
                    for num in range(start, end + 1):
                        simulate_feature(num)
                        time.sleep(0.5)
                else:
                    print(Fore.RED + "Invalid range")
                    time.sleep(1)
            except ValueError:
                print(Fore.RED + "Invalid input")
                time.sleep(1)
        elif choice.isdigit():
            num = int(choice)
            if 1 <= num <= total_features:
                simulate_feature(num)
            else:
                print(Fore.RED + "Invalid feature number")
                time.sleep(1)
        else:
            print(Fore.RED + "Invalid input")
            time.sleep(1)

def simulate_feature(num):
    clear()
    banner()
    
    # Organized features by category
    if 1 <= num <= 20:
        # Basic Wi-Fi Tools
        features = {
            1: ("Wi-Fi Channel Scanner", "Scanning all 2.4GHz and 5GHz channels"),
            2: ("Signal Strength Mapper", "Creating heatmap of signal strengths"),
            3: ("MAC Address Changer", "Randomizing your MAC address"),
            4: ("Hidden SSID Revealer", "Detecting hidden network names"),
            5: ("Wi-Fi Traffic Sniffer", "Capturing raw Wi-Fi packets"),
            6: ("Packet Injection Test", "Testing packet injection capability"),
            7: ("Interface Mode Switcher", "Switching between managed/monitor modes"),
            8: ("Wi-Fi Adapter Info", "Displaying detailed adapter information"),
            9: ("Regulatory Domain Check", "Checking local wireless regulations"),
            10: ("Supported Rates Analyzer", "Listing supported data rates"),
            11: ("Beacon Frame Analyzer", "Analyzing beacon frame contents"),
            12: ("Authentication Test", "Testing authentication methods"),
            13: ("Association Test", "Testing association with AP"),
            14: ("Power Save Check", "Checking power save capabilities"),
            15: ("HT/VHT Info", "Displaying HT/VHT capabilities"),
            16: ("Supported Channels", "Listing all supported channels"),
            17: ("Bitrate Test", "Testing different bitrates"),
            18: ("Fragmentation Test", "Testing frame fragmentation"),
            19: ("RTS/CTS Test", "Testing RTS/CTS mechanism"),
            20: ("Power Level Check", "Checking transmission power levels")
        }
    elif 21 <= num <= 40:
        # Advanced Attacks
        features = {
            21: ("KRACK Attack", "Simulating Key Reinstallation Attack"),
            22: ("Fragmentation Attack", "Performing WPA2 fragmentation attack"),
            23: ("Michael Exploit", "Exploiting TKIP MIC vulnerability"),
            24: ("Honeypot Detector", "Detecting fake access points"),
            25: ("WPA3 Downgrade", "Attempting WPA3 downgrade attack"),
            26: ("PMKID Attack", "Capturing PMKID for offline cracking"),
            27: ("EAPOL Attack", "Exploiting EAPOL frames"),
            28: ("Rogue AP Detector", "Identifying rogue access points"),
            29: ("WPS Lock Bypass", "Attempting to bypass WPS lock"),
            30: ("MAC Filter Bypass", "Bypassing MAC address filtering"),
            31: ("WEP Chop-Chop", "Performing chop-chop attack"),
            32: ("WEP Fragmentation", "Performing fragmentation attack"),
            33: ("ARP Replay", "Performing ARP replay attack"),
            34: ("Caffe Latte", "Performing Caffe Latte attack"),
            35: ("Hirte Attack", "Performing Hirte attack"),
            36: ("Authentication DoS", "Performing authentication flood"),
            37: ("Association DoS", "Performing association flood"),
            38: ("Deauthentication Flood", "Flooding deauth packets"),
            39: ("Disassociation Flood", "Flooding disassociation packets"),
            40: ("Beacon Flood", "Flooding beacon frames")
        }
    elif 41 <= num <= 60:
        # Network Analysis
        features = {
            41: ("Spectrum Analyzer", "Analyzing RF spectrum usage"),
            42: ("Channel Utilization", "Calculating channel utilization"),
            43: ("Packet Decoder", "Decoding captured packets"),
            44: ("Protocol Analyzer", "Analyzing network protocols"),
            45: ("Traffic Classifier", "Classifying network traffic"),
            46: ("Throughput Test", "Measuring network throughput"),
            47: ("Latency Test", "Measuring network latency"),
            48: ("Jitter Test", "Measuring packet jitter"),
            49: ("Packet Loss Test", "Measuring packet loss"),
            50: ("Bandwidth Monitor", "Monitoring bandwidth usage"),
            51: ("Client Locator", "Triangulating client position"),
            52: ("Signal Propagation", "Analyzing signal propagation"),
            53: ("Interference Detection", "Detecting RF interference"),
            54: ("Noise Floor Measurement", "Measuring noise floor"),
            55: ("SNR Calculator", "Calculating signal-to-noise ratio"),
            56: ("Data Rate Analysis", "Analyzing data rates"),
            57: ("Frame Analysis", "Analyzing frame types"),
            58: ("QoS Analyzer", "Analyzing Quality of Service"),
            59: ("MCS Index Analyzer", "Analyzing MCS indices"),
            60: ("Beacon Interval Analysis", "Analyzing beacon intervals")
        }
    elif 61 <= num <= 80:
        # Security Testing
        features = {
            61: ("Vulnerability Scanner", "Scanning for known vulnerabilities"),
            62: ("Penetration Test", "Performing penetration test"),
            63: ("Security Audit", "Conducting security audit"),
            64: ("Encryption Test", "Testing encryption strength"),
            65: ("Firewall Test", "Testing firewall rules"),
            66: ("IDS/IPS Test", "Testing intrusion detection/prevention"),
            67: ("RADIUS Test", "Testing RADIUS server security"),
            68: ("Captive Portal Test", "Testing captive portal security"),
            69: ("VPN Detection", "Detecting VPN usage"),
            70: ("Tunnel Detection", "Detecting tunneling protocols"),
            71: ("MITM Detection", "Detecting man-in-the-middle"),
            72: ("Evil Twin Detection", "Detecting evil twin APs"),
            73: ("ARP Spoof Detection", "Detecting ARP spoofing"),
            74: ("DNS Spoof Detection", "Detecting DNS spoofing"),
            75: ("DHCP Spoof Detection", "Detecting rogue DHCP"),
            76: ("SSL Strip Detection", "Detecting SSL stripping"),
            77: ("HSTS Bypass Test", "Testing HSTS bypass"),
            78: ("Cookie Hijack Test", "Testing cookie hijacking"),
            79: ("Session Fixation Test", "Testing session fixation"),
            80: ("CSRF Test", "Testing CSRF vulnerabilities")
        }
    else:
        # Miscellaneous (81-100)
        features = {
            81: ("Wi-Fi Pineapple", "Simulating Wi-Fi Pineapple"),
            82: ("Firmware Analyzer", "Analyzing device firmware"),
            83: ("OTA Update Sniffer", "Sniffing OTA updates"),
            84: ("IoT Device Test", "Testing IoT device security"),
            85: ("Bluetooth Scanner", "Scanning Bluetooth devices"),
            86: ("Zigbee Sniffer", "Sniffing Zigbee traffic"),
            87: ("Z-Wave Analyzer", "Analyzing Z-Wave networks"),
            88: ("RFID Scanner", "Scanning RFID devices"),
            89: ("NFC Analyzer", "Analyzing NFC communication"),
            90: ("GPS Spoofing", "Simulating GPS spoofing"),
            91: ("SDR Scanner", "Software-defined radio scanning"),
            92: ("GSM Sniffer", "Sniffing GSM traffic"),
            93: ("LTE Analyzer", "Analyzing LTE signals"),
            94: ("5G Scanner", "Scanning 5G networks"),
            95: ("Satcom Test", "Testing satellite comms"),
            96: ("Maritime Comms", "Analyzing maritime signals"),
            97: ("Aviation Comms", "Analyzing aviation signals"),
            98: ("Military Band Scan", "Scanning military bands"),
            99: ("Emergency Comms", "Analyzing emergency signals"),
            100: ("Quantum Crypto", "Simulating quantum crypto")
        }
    
    name, desc = features.get(num, ("Unknown Feature", "No description available"))
    
    print(Fore.CYAN + f"\n[~] Feature #{num}: {name}")
    print(Fore.YELLOW + f"Description: {desc}\n")
    
    print_with_spinner("Executing feature", 3)
    
    # Simulate different outcomes
    outcome = random.random()
    if outcome > 0.8:  # 20% chance of warning
        print(Fore.YELLOW + "\n[!] Warning: Partial functionality")
        print("Some aspects may not work as expected")
    elif outcome > 0.9:  # 10% chance of error
        print(Fore.RED + "\n[✖] Error: Feature failed")
        print("Check system requirements and try again")
    else:  # 70% chance of success
        print(Fore.GREEN + f"\n[✔] {name} completed successfully")
        
        # Simulate output if successful
        if random.random() > 0.5:
            print(Fore.CYAN + "\nGenerated output:")
            if num in [1, 2, 3]:
                print(f"Channel {random.randint(1,165)}: {random.randint(30,90)}% signal")
            elif num in [21, 22, 23]:
                print(f"Vulnerability found: {random.choice(['CVE-2023-1234', 'CVE-2022-4567'])}")
            elif num in [41, 42, 43]:
                print(f"Analyzed {random.randint(100,1000)} packets")
            elif num in [61, 62, 63]:
                print(f"Found {random.randint(1,5)} security issues")
            elif num in [81, 82, 83]:
                print(f"Discovered {random.randint(1,3)} devices")
    
    log_attack(f"Feature #{num}: {name}", None, outcome <= 0.9)
    input(Fore.CYAN + "\nPress Enter to continue...")

if __name__ == "__main__":
    try:
        main_menu()
    except KeyboardInterrupt:
        print(Fore.RED + "\n\n[!] Interrupted by user. Exiting...")
        sys.exit(0)
