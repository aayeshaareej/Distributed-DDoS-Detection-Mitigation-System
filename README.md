# Distributed-DDoS-Detection-Mitigation-System
This project is a high-performance Distributed Denial of Service (DDoS) Detection and Mitigation System that combines C-based packet processing with MPI parallelization and a Python real-time dashboard.
# 🚀 Distributed DDoS Detection & Mitigation System

## 📌 Project Overview

This project is a **high-performance Distributed Denial of Service (DDoS) Detection and Mitigation System** that combines **C-based packet processing** with **MPI parallelization** and a **Python real-time dashboard**. The system detects attacks using statistical algorithms (PCA, CUSUM) and implements real-time packet filtering with iterative mitigation strategies.

---

## 🎯 Key Features

* **Parallel Packet Processing** – MPI-based distribution across multiple cores/nodes
* **Statistical Attack Detection** – PCA (Principal Component Analysis) + CUSUM (Cumulative Sum) algorithms
*  **Model Attack Detection** - Random forest used
* **Real-time Mitigation** – Active packet filtering with rate limiting and complete blocking
* **Iterative Response** – Multi-phase mitigation with escalation logic
* **Comprehensive Dashboard** – Flask-based web UI with Plotly visualizations
* **Performance Metrics** – CPU/memory usage, processing latency, detection lead time
* **Top Attackers Analysis** – Real-time identification of malicious IPs
* **Effectiveness Tracking** – Attack traffic dropped vs. collateral impact metrics

---

## 🏗️ Project Architecture

```
ddos-detection-system/
├── Project.c                 # C core with MPI, pcap, detection algorithms
├── gui.py                    # Flask dashboard with real-time visualizations
├── ddos_live_data.json       # Live data bridge (C → Python)
├── README.md                 # This file
```

**Data Flow:**
```
Live Traffic → pcap capture → MPI distribution → Statistical analysis
      ↓
Attack detection → Mitigation rules → Packet filtering → Effectiveness metrics
      ↓
JSON data → Flask dashboard → Real-time visualization
```

---

## 📚 Required Libraries & Tools

### **C/C++ Requirements:**
- **MPI** (OpenMPI or MPICH) – for parallel processing
- **libpcap** – for packet capture
- **GCC/Clang** – C compiler with C99 support
- **math library** – linked with `-lm`

### **Python Requirements:**
- **Python 3.8+**
- **Flask** – web framework
- **Plotly** – interactive charts
- **NumPy** – numerical computations
- **Font Awesome & Bootstrap** (CDN)

---

## ⚙️ Environment Setup

### **1️⃣ Install System Dependencies**

#### **Ubuntu/Debian:**
```bash
sudo apt update
sudo apt install -y libpcap-dev openmpi-bin openmpi-common openmpi-doc \
                    libopenmpi-dev python3 python3-pip gcc build-essential
```

#### **macOS:**
```bash
brew install libpcap open-mpi python3
```

#### **Windows (WSL2 recommended):**
```bash
# In WSL2 Ubuntu
sudo apt update
sudo apt install -y libpcap-dev openmpi-bin libopenmpi-dev python3 python3-pip
```

### **2️⃣ Install Python Dependencies**
```bash
pip install -r requirements.txt
```

Or manually:
```bash
pip install flask plotly numpy
```

### **3️⃣ Compile the C Program**
```bash
mpicc -o ddos_detector Project.c -lpcap -lm -O3
```

---

## ▶️ How to Run the System

### **Step 1: Start the C Detection Engine**
```bash
sudo mpirun -np 4 ./ddos_detector
```
> **Note:** Requires `sudo` for packet capture. Adjust `-np 4` based on available CPU cores.

### **Step 2: Start the Python Dashboard**
```bash
python3 gui.py
```
Or with debug mode:
```bash
python3 gui.py &
```

### **Step 3: Access the Dashboard**
Open your browser and navigate to:
```
http://localhost:5000
```

### **Step 4: Generate Test Traffic (Optional)**
To test the system, you can simulate attack traffic:
```bash
# Simple ping flood (requires hping3)
sudo hping3 -S --flood -p 80 [TARGET_IP]

# Or with multiple tools
sudo apt install hping3
```

---

## 🖥️ Dashboard Features

### **Real-time Monitoring:**
- **Traffic Overview** – Packet rates, throughput, protocol ratios
- **System Resources** – CPU, memory, processing latency
- **Detection Metrics** – Statistical alerts, confidence scores
- **Mitigation Status** – Active rules, effectiveness, collateral impact
- **Attack Analysis** – Top malicious IPs, traffic distribution

### **Auto-refresh:**
- Dashboard updates every **10 seconds**
- API endpoints for programmatic access:
  - `http://localhost:5000/api/data` – Latest metrics
  - `http://localhost:5000/api/history` – Historical trends

---

## 🔧 Configuration Options

### **C Program Parameters:**
- `TRAFFIC_TIMEOUT` – Auto-stop after inactivity (seconds)
- `WINDOW_SIZE` – Statistical analysis window
- `MAX_IPS` – Maximum tracked IP addresses
- `MIN_TRAINING_SAMPLES` – Minimum samples for PCA training

### **Dashboard Customization:**
- Thresholds in `gui.py`: `get_traffic_status_color()`
- Chart colors and layouts in visualization functions
- Refresh intervals in JavaScript and update threads

---

## 🧪 Testing & Simulation

### **1. Normal Traffic Test:**
```bash
# Use normal browsing or wget
wget -O /dev/null http://example.com
```

### **2. Attack Simulation:**
```bash
# SYN Flood simulation
sudo hping3 -S --flood -p 80 localhost

# UDP Flood simulation
sudo hping3 --udp --flood -p 53 localhost
```

### **3. Performance Benchmark:**
Monitor system resources during detection:
```bash
watch -n 1 "ps aux | grep ddos_detector"
```

---

## 📊 Output Examples

### **Terminal Output (C Program):**
```
🚀 DISTRIBUTED DDoS DETECTION & REAL-TIME MITIGATION SYSTEM
📡 MPI Processes: 4 | Interface: eth0
🔧 Hash-based packet distribution across 4 ranks

╔════════════════════════════════════════════════════════════════════╗
║                 PHASE 1: DDoS DETECTION REPORT                   ║
╠════════════════════════════════════════════════════════════════════╣
║ 🔴 DETECTION STATUS: ATTACK CONFIRMED                           ║
║    Type: UDP Flood              Confidence: 85.7%               ║
║ 📊 TRAFFIC ANALYSIS (PRE-MITIGATION)                            ║
║    Total Packets: 125,847       Packet Rate: 12,584.7 pps      ║
║    Unique IPs: 42               Global Entropy: 0.87           ║
```

### **Dashboard Metrics:**
- **Packet Rate:** Visual threshold alerts (green/yellow/red)
- **Entropy Analysis:** Distributed vs. single-source detection
- **Mitigation Effectiveness:** Real-time blocking statistics
- **Top Attackers:** IP addresses with traffic percentages

---

## 🚨 Mitigation Strategies

The system implements **3-phase mitigation**:

1. **Phase 1:** Rate limiting for moderate offenders
2. **Phase 2:** Complete blocking for persistent attackers
3. **Phase 3:** Rule escalation based on effectiveness

**Effectiveness metrics tracked:**
- Attack traffic dropped percentage
- Collateral impact (legitimate traffic affected)
- Total packets blocked
- Iteration count

---

## ⚠️ Important Notes

1. **Run with sudo** – Packet capture requires root privileges
2. **Network Interface** – Default is `eth0`, modify in `Project.c` if needed
3. **MPI Configuration** – Ensure proper MPI installation for distributed processing
4. **Firewall Rules** – May need adjustment for local testing
5. **Resource Usage** – The system is designed for high-performance; monitor resource consumption

---

## 🐛 Troubleshooting

### **Common Issues:**

1. **"pcap_open_live failed"**
   ```bash
   sudo ip link set eth0 up  # Enable interface
   sudo ifconfig eth0 promisc  # Set promiscuous mode
   ```

2. **MPI initialization errors**
   ```bash
   export OMPI_MCA_btl_vader_single_copy_mechanism=none
   ```

3. **Dashboard not loading**
   ```bash
   # Check Flask is running
   netstat -tulpn | grep 5000
   
   # Check JSON data file
   ls -la ddos_live_data.json
   ```

4. **Compilation errors**
   ```bash
   # Ensure all dependencies installed
   sudo apt install libpcap-dev openmpi-bin libopenmpi-dev
   ```

---

## 📈 Performance Considerations

- **MPI Scaling:** Linear scaling with core count
- **Memory Usage:** ~1MB per 10,000 tracked IPs
- **Detection Latency:** <10ms for statistical algorithms
- **Dashboard Overhead:** <5% CPU with 4-core system

---

## 🔮 Future Enhancements

1. **Machine Learning Integration** – Neural networks for anomaly detection
2. **Cloud Deployment** – Kubernetes orchestration
3. **API Integration** – External threat intelligence feeds
4. **Mobile Dashboard** – Responsive design for mobile devices
5. **Historical Analysis** – Long-term trend storage and reporting

---

## 👨‍💻 Author

**DDoS Detection System Team**  
*Advanced Network Security Project*  
*Real-time Traffic Analysis & Mitigation*

---

## 📄 License

This project is for **educational and research purposes only**. Use responsibly and in compliance with all applicable laws and network policies.

---

## 🙏 Acknowledgments

- **MPI Forum** – Parallel computing standard
- **libpcap developers** – Packet capture library
- **Plotly & Flask communities** – Visualization and web framework
- **Academic research** in statistical anomaly detection

---

**🚀 Happy DDoS Hunting!**
