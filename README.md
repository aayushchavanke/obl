# THE OBSIDIAN LENS
*Next-Generation Network Forensic and Identity Tracking Platform*

The Obsidian Lens (formerly BENFET) is a high-availability, administrative-level network forensics and active-defense platform. It couples raw packet sniffing natively with a 49-parameter machine learning classifier to mathematically fingerprint, track, and block network intruders.

---

## 🏗️ System Architecture & Data Flow

The platform is split into a **Node/Next.js frontend UI** and a **Python/Flask ML backend**. The entire data lifecycle operates within a secure environment:

1. **Ingestion (Packet Capture)**
   - **Live Capture**: Uses `scapy` linked to the Windows Npcap driver. Operating purely asynchronously in a thread-safe environment, it captures native layer-2 / layer-3 traffic without blocking the API. 
   - **OTX Mode**: Pulls traffic that intersects specifically with known Open Threat Exchange heuristics.
   - **Manual PCAP**: Allows forensic upload of pre-recorded `.pcap` files.

2. **Feature Extraction (`pcap_parser.py`)**
   - The raw byte flow is parsed into 49 mathematical features specifically corresponding to the CICIDS2017 dataset schema (e.g., *Inter-Arrival Times (IAT), Forward/Backward Packet Length Variance, Flow Bytes/s*).

3. **Inference & XAI Insight Pipeline (`classifier.py`)**
   - The 49-feature array is fed into a locally trained **Weighted Random Forest**.
   - The model mathematically projects the traffic against 7 known profiles.
   - **XAI (Explainable AI)**: Instead of a "black box" tag, the algorithm extracts its own `.feature_importances_` variance, translating the exact numeric anomalies (e.g., *abnormally high backward packet length standard deviation*) into a human-readable English justification.

4. **Identity Graph Mapping (`identity_db.py`)**
   - Packets are heavily correlated by **MAC Address**.
   - Because MACs are permanent physical hardware identifiers on the local layer, the system utilizes them to establish a unique "Identity".
   - The database then logically chains all dynamically shifting IP Addresses associated with that MAC to that singular Identity. The 49-parameter behavior profile is permanently tied to that user.

5. **Firewall Enforcement (Active Defense)**
   - When the professional Administrator activates a "Block", the SQLite Database queries the relationship graph.
   - It fetches every single IP address ever utilized by that MAC.
   - The backend fires `netsh advfirewall` instructions directly to the Windows Kernel, establishing hard block-drops for all associated IPs simultaneously.

---

## 🧠 Machine Learning Engine

The system is fortified by an ML model hardened against the **CICIDS2017** threat topology. 

*   **Algorithm**: Weighted Random Forest
*   **Dimensionality**: 49 Features
*   **Training Database**: 200,000 real-world flow structures
*   **Cross-Validation Accuracy**: 99.96%

### Detected Threat Profiles (Categories)
The network monitors flow shapes to dynamically snap traffic into one of seven profiles:

1. **`web_browser`** (Safe baseline: Normal browsing behavior, standard TLS handshakes)
2. **`apt_exfiltration`** (Advanced Persistent Threat: Slow, methodical data bleeding)
3. **`botnet`** (Command & Control: Rhythmic, automated beacon heartbeat)
4. **`brute_force_ssh`** (Access Attack: Volatile spikes in failed authentication packet structures)
5. **`ddos_attack`** (Denial of Service: Flooding and volumetric overload)
6. **`malware_c2`** (Trojan Check-ins: Small, encrypted payloads phoning servers)
7. **`port_scan`** (Reconnaissance: Rapid, sequential TCP/UDP port knocking without data transfer)

---

## 🚀 Execution & Administration

Because The Obsidian Lens operates at the lowest levels of network infrastructure, **it absolutely mandates Administrator execution.**

Without Administrator rights:
- Continuous Live `Npcap` monitoring will fail to read the network card.
- `netsh` Firewall block rules will fail dynamically.

**To Run the Platform:**
Always launch the unified batch script:
`start_obsidian.bat` (located in the project root)
*Double-clicking this file will automatically request Windows UAC Administrator Elevation before bridging the Next.js and Flask pipelines.*
