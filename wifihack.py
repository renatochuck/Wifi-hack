import time
import random
import os
import sys
from colorama import Fore, Style, init

init(autoreset=True)

def clear():
    os.system('cls' if os.name == 'nt' else 'clear')

# Spinning cursor for animations
def spinning_cursor():
    while True:
        for cursor in '|/-\\':
            yield cursor

spinner = spinning_cursor()

def banner():
    print(Fore.GREEN + Style.BRIGHT + """
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

   Wi-Fi Attack Tool v1.1
      Author: @renatochuck
    For Ethical Learning Only!
""")

wifi_networks = [
    "Renato_Home_5G",
    "Free_WiFi_24G",
    "Guest_Café",
    "School_AP",
    "Hidden_Network"
]

vendors = ["Cisco", "Netgear", "TP-Link", "D-Link", "ASUS", "Linksys"]

client_devices = [
    "John's iPhone", "Office-Laptop", "Android-XYZ", "Gaming-PC", "SmartTV", "Tablet-001"
]

def random_mac():
    return ":".join(f"{random.randint(0, 255):02x}" for _ in range(6))

def print_with_spinner(text, duration=2):
    print(text, end=' ', flush=True)
    end_time = time.time() + duration
    while time.time() < end_time:
        sys.stdout.write(next(spinner))
        sys.stdout.flush()
        time.sleep(0.1)
        sys.stdout.write('\b')
    print("✔")

def main_menu():
    while True:
        clear()
        banner()
        print(Fore.CYAN + "\n[1] Scan Nearby Wi-Fi")
        print("[2] Exit")
        choice = input(Fore.YELLOW + "\nSelect Option: ")
        if choice == "1":
            scan_wifi()
        elif choice == "2":
            print(Fore.RED + "\nExiting... Stay safe!\n")
            break
        else:
            print(Fore.RED + "Invalid input. Try again.")
            time.sleep(1)

def scan_wifi():
    clear()
    banner()
    print(Fore.CYAN + "\n[+] Scanning for Wi-Fi Networks...\n")
    print_with_spinner("Scanning")
    print()
    for idx, wifi in enumerate(wifi_networks, 1):
        signal = random.randint(40, 99)
        print(Fore.GREEN + f"[{idx}] {wifi}  Signal: {signal}%")
        time.sleep(0.4)

    selected = input(Fore.YELLOW + "\nSelect Wi-Fi Name or Number: ")
    if selected.isdigit() and 1 <= int(selected) <= len(wifi_networks):
        target = wifi_networks[int(selected) - 1]
    elif selected in wifi_networks:
        target = selected
    else:
        print(Fore.RED + "\nInvalid selection.")
        time.sleep(1)
        return

    wifi_options(target)

def wifi_options(target):
    clear()
    banner()
    print(Fore.CYAN + f"\n[~] Scanning '{target}'...\n")
    print_with_spinner("Gathering network info", 3)

    mac = random_mac()
    channel = random.choice([1,6,11])
    vendor = random.choice(vendors)
    clients = random.sample(client_devices, k=3)

    print(Fore.GREEN + f"[✔] Found target: {target}")
    print(Fore.MAGENTA + f"[!] Encryption: WPA2 | Handshake Available | Clients: {len(clients)}")
    print(Fore.CYAN + f"    MAC: {mac} | Channel: {channel} | Vendor: {vendor}\n")
    print(Fore.CYAN + "Connected Clients:")
    for i, c in enumerate(clients, 1):
        print(Fore.YELLOW + f" - {c} [{random_mac()}]")

    while True:
        print(Fore.YELLOW + f"\nWhat do you want to do with '{target}'?")
        print("[1] Crack Password (brute-force)")
        print("[2] Kick Users from Network")
        print("[3] Create Fake Wi-Fi (Evil Twin)")
        print("[4] Back to Main Menu")

        opt = input(Fore.CYAN + "\nSelect Option: ")

        if opt == "1":
            crack_password(target, clients)
        elif opt == "2":
            kick_users(target, clients)
        elif opt == "3":
            fake_ap(target, clients)
        elif opt == "4":
            break
        else:
            print(Fore.RED + "Invalid choice.\n")

def crack_password(target, clients):
    clear()
    banner()
    print(Fore.YELLOW + f"\n[~] Starting WPA2 password cracking on {target}...\n")
    print_with_spinner("Capturing handshake packets", 4)

    fake_passwords = [
        "password123", "admin1234", "letmein", "12345678", "qwerty2025", "freewifi", "hacker2025"
    ]

    for attempt in range(1, 11):
        pwd_try = random.choice(fake_passwords) + str(random.randint(0,99))
        print(Fore.MAGENTA + f"[*] Trying password: {pwd_try}")
        time.sleep(0.6)

    cracked_pass = f"{target}_@hack{random.randint(1000,9999)}"
    print(Fore.GREEN + f"\n[✔] Password Cracked: {cracked_pass}\n")

    print(Fore.YELLOW + "[~] Automatically kicking users to force reconnect...\n")
    kick_users(target, clients, auto=True)

    print(Fore.YELLOW + "[~] Creating Evil Twin Wi-Fi access point...\n")
    fake_ap(target, clients, auto=True)

    print_attack_summary(target, cracked_pass, clients)

    input(Fore.CYAN + "Press Enter to return to menu...")

def kick_users(target, clients, auto=False):
    if not auto:
        clear()
        banner()
        print(Fore.YELLOW + f"\n[~] Sending deauth packets to {target} clients...\n")

    for i, client in enumerate(clients, 1):
        print(Fore.RED + f"[×] Client '{client}' disconnected.")
        time.sleep(0.8)

    print(Fore.GREEN + "[✔] All users disconnected.\n")

    if not auto:
        input(Fore.CYAN + "Press Enter to return...")

def fake_ap(target, clients, auto=False):
    if not auto:
        clear()
        banner()

    print(Fore.YELLOW + f"\n[~] Creating fake Wi-Fi clone of {target}...")
    print_with_spinner("Broadcasting Evil Twin AP", 3)
    print(Fore.GREEN + f"[✔] Evil Twin AP '{target}_FREE' now broadcasting.\n")

    # Fake clients connecting to Evil Twin
    print(Fore.CYAN + "Fake clients connecting to Evil Twin AP:")
    for i in range(random.randint(1, len(clients))):
        fake_client = random.choice(clients)
        fake_ip = f"192.168.1.{random.randint(2,254)}"
        print(Fore.YELLOW + f" - {fake_client} connected from {fake_ip}")
        time.sleep(0.7)

    if not auto:
        input(Fore.CYAN + "Press Enter to return...")

def print_attack_summary(target, password, clients):
    print(Fore.CYAN + "\n=== Attack Summary ===")
    print(Fore.GREEN + f"Target: {target}")
    print(Fore.GREEN + f"Password Cracked: {password}")
    print(Fore.GREEN + f"Clients kicked: {len(clients)}")
    print(Fore.GREEN + f"Evil Twin AP: {target}_FREE")
    print(Fore.GREEN + "Duration: Approx. 5 minutes")
    print(Fore.CYAN + "======================\n")

if __name__ == "__main__":
    main_menu()
