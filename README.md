# 📡 Wi-Fi Brute Force Tool

![Wi-Fi Brute Force](![image](https://github.com/user-attachments/assets/cc91ba6c-d161-4674-a04d-70fadc917ca2)
)  

[![Telegram](https://img.shields.io/badge/Telegram-Group-blue)](https://t.me/yourgroup) [![GitHub](https://img.shields.io/badge/GitHub-Repo-black)](https://github.com/rave-ns/Wifi_Brute)

---

## ⚠️ DISCLAIMER ⚠️

🚨 **FOR EDUCATIONAL & LEGAL USE ONLY!** 🚨  
This tool is intended for **authorized penetration testing** and **security research**. **Do not** use it on networks you don't own or have explicit permission to test. Unauthorized access is illegal and may result in severe legal consequences.

---

## ✨ Features

- 📡 **Wi-Fi Network Scanning** – Detect nearby wireless networks.
- 🔑 **Dictionary Attack** – Brute-force Wi-Fi passwords using a provided wordlist.
- 📝 **Result Logging** – Save cracked passwords and attempted combinations.
- 💻 **Cross-Platform** – Works on **Windows** & **Linux** (Run as Administrator/root).
- 🎨 **Enhanced UI** – Uses the `rich` library for a sleek interface.

---

## 📋 Requirements

- 🐍 **Python 3.7+**
- 🛡️ **Administrator/root privileges**
  - **Windows:** Run the script in an **elevated Command Prompt** as **Admin**.
  - **Linux:** Run with `sudo`.
- 📶 **Compatible Wi-Fi adapter** (standard mode for `pywifi`).
- 📚 **Dependencies:**
  ```bash
  pip install pywifi rich comtypes
  ```

---

## 🚀 Installation

Clone the repository and navigate to the project directory:

```bash
git clone https://github.com/rave-ns/Wifi_Brute.git
cd Wifi_Brute
```

Run the script:

```bash
python wifi_brute.py
```

---

## 📜 Usage

1. Ensure your Wi-Fi adapter is in the correct mode.
2. Provide a **password list** (`passwords.txt`).
3. Run the script and monitor the output.

---

## 🎯 Example Output

```plaintext
[+] Scanning for Wi-Fi networks...
[✔] Found: Home_WiFi
[🔄] Trying password: 12345678
[❌] Incorrect password...
[🔄] Trying password: password123
[✅] Cracked! Password: password123
```

---

## 🎭 Legal Disclaimer

This tool is strictly for **educational and penetration testing purposes only**. Unauthorized use is **illegal** and may result in legal action. The developers are not responsible for any misuse.

---

## 🌐 Connect with Us

📢 **Join our community for updates and discussions:**

- 📡 **Telegram:** [Join Now](https://t.me/yourgroup)
- 🖥️ **GitHub:** [Project Page](https://github.com/rave-ns/Wifi_Brute)

---

💀 **Hack the Planet... But Stay Legal!** 💀
