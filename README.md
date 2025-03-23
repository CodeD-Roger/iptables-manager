
# 🛡️ IPTables Manager
---

`iptables-manager.sh` is a powerful **interactive Bash script** to manage your Linux firewall rules using `iptables` in a clear, secure, and stylish terminal interface.

---

## 🔧 What It Does

- **🧭 Displays a complete dashboard of your firewall configuration.**
- **🧩 Lets you add, delete, and customize rules with guidance.**
- **💾 Supports saving, loading, and managing firewall profiles.**
- **📋 Offers ready-to-use server presets (Web, FTP, VPN, etc.).**
- **🧪 Includes a test mode with auto rollback after timeout.**
- **🔍 Allows real-time auditing and filtering of active rules.**

---

## 🎯 Menu Features

- **📊 Live dashboard** showing open ports, allowed services, and rule stats.
- **➕ Custom rule creation** (with support for timed rules).
- **🗑 Delete specific rules**, flush chains, or reset the firewall.
- **💼 Profile management** with backups before applying changes.
- **🚀 Quick toggle modes** (enhanced security / maintenance).
- **🧱 Default policy control** for each chain (INPUT, OUTPUT, FORWARD).
- **📈 Audit and monitoring tools** (recent activity, exportable reports).
- **🧰 Preset templates** for server types (FTP, VPN, database, etc.).
- **🧪 Safe test mode** to try rules temporarily with auto-restore.

---

## 🚀 Installation and Launch

### 1️⃣ Clone the repository
```bash
git clone https://github.com/CodeD-Roger/iptables-manager.git
cd iptables-manager
```

### 2️⃣ Make the script executable
```bash
sudo chmod +x iptables-manager.sh
```

### 3️⃣ Run the script as root
```bash
sudo ./iptables-manager.sh
```

---

## 📜 Sample Presets Included

| Preset | Ports Opened |
|--------|--------------|
| **Basic server** | 22 (SSH) |
| **Web server** | 22, 80, 443 |
| **Mail server** | 25, 465, 587, 110, 995, 143, 993 |
| **VPN (WireGuard)** | 22, 51820/UDP |
| **Database server** | 3306, 5432, 27017, 6379 |
| **FTP server** | 21, 1024-1048 |



---


## ⚠️ Warning

**Do not apply firewall rules unless you know what you're doing.**
A wrong configuration can block your SSH access or disconnect services.

Use the **test mode** or make backups before any major change.
