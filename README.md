![image](https://github.com/user-attachments/assets/929bdf86-5808-480f-90cc-cc1d26a24fda)


# ▄████▄   ▒█████   ██▓███   ▄▄▄       ██▀███   ▒█████   ██▀███   ▒█████   ▄████▄  
## ▒██▀ ▀█  ▒██▒  ██▒▓██░  ██▒▒████▄    ▓██ ▒ ██▒▒██▒  ██▒▓██ ▒ ██▒▒██▒  ██▒▒██▀ ▀█  
## ▒▓█    ▄ ▒██░  ██▒▓██░ ██▓▒▒██  ▀█▄  ▓██ ░▄█ ▒▒██░  ██▒▓██ ░▄█ ▒▒██░  ██▒▒▓█    ▄  
## ▒▓▓▄ ▄██▒▒██   ██░▒██▄█▓▒ ▒░██▄▄▄▄██ ▒██▀▀█▄  ▒██   ██░▒██▀▀█▄  ▒██   ██░▒▓▓▄ ▄██▒
## ▒ ▓███▀ ░░ ████▓▒░▒██▒ ░  ░ ▓█   ▓██▒░██▓ ▒██▒░ ████▓▒░░██▓ ▒██▒░ ████▓▒░▒ ▓███▀ ░
## ░ ░▒ ▒  ░░ ▒░▒░▒░ ▒▓▒░ ░  ░ ▒▒   ▓▒█░░ ▒▓ ░▒▓░░ ▒░▒░▒░ ░ ▒▓ ░▒▓░░ ▒░▒░▒░ ░ ░▒ ▒  ░
##   ░  ▒     ░ ▒ ▒░ ░▒ ░       ▒   ▒▒ ░  ░▒ ░ ▒░  ░ ▒ ▒░   ░▒ ░ ▒░  ░ ▒ ▒░   ░  ▒   
## ░          ░ ░ ░  ░░         ░   ▒     ░░   ░ ░ ░ ░ ▒    ░░   ░ ░ ░ ░ ▒  ░        
## ░ ░            ░ ░                 ░  ░   ░         ░ ░     ░           ░ ░  
##                             Advanced Wi-Fi Brute Force Tool
#
# [ TELEGRAM: @Asqlan - @MLBOR | GITHUB: rave-ns ]
#
# ---------------------------------------------------------------------------
# DISCLAIMER: This tool is for educational and authorized penetration testing
# purposes ONLY. Use it on networks you own or have explicit permission to test.
# Unauthorized use is illegal and may result in severe penalties.
# ---------------------------------------------------------------------------

## Features

- **Wi-Fi Network Scanning:** Detect nearby wireless networks.
- **Dictionary Attack:** Brute-force Wi-Fi passwords using a provided wordlist.
- **Result Logging:** Save cracked passwords and attempted combinations.
- **Cross-Platform:** Works on Windows and Linux (Run as Administrator/root).
- **Enhanced UI:** Uses the [rich](https://github.com/willmcgugan/rich) library for a sleek interface.

## Requirements

- **Python 3.7+**
- **Administrator/root privileges**  
  - Windows: Run the script in an elevated Command Prompt.
  - Linux: Run with `sudo`.
- **Compatible Wi-Fi adapter** in proper mode (standard mode for pywifi)
- [pywifi](https://pypi.org/project/pywifi/)  
- [rich](https://pypi.org/project/rich/) (optional, for enhanced UI)  
- [comtypes](https://pypi.org/project/comtypes/) (Windows only)

## Installation

1. **Clone the repository:**

   ```sh
   git clone https://github.com/rave-ns/WiFiCracker.git
   cd WiFiCracker
