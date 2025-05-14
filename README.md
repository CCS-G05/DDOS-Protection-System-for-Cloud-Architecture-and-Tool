# DDoS Protection System for Cloud Platforms

This repository provides solutions for protecting cloud platforms from Distributed Denial of Service (DDoS) attacks. It incorporates various techniques to detect, mitigate, respond to, and recover from DDoS attacks, ensuring high availability and security for cloud environments.

## Key Features:
- **DDoS Detection**: Using anomaly-based and signature-based methods, enhanced with machine learning algorithms to differentiate malicious traffic.
- **Mitigation**: Implements rate limiting, traffic filtering, and diversion techniques like sinkholing and scrubbing.
- **Response**: Real-time alerts for system administrators and automated activation of defensive protocols.
- **Recovery**: Restores cloud services to normal operation with minimal downtime.
- **Integration with Cloud Services**: Utilizes AWS Shield, Azure DDoS Protection, and Google Cloud Armor to bolster defense strategies.
- **Hybrid Solutions**: Combines on-premise hardware with cloud resources for broader coverage and flexibility.

## Files and Usage:

### 1. `generate_and_plot_traffic.py`
This script generates and plots traffic patterns, simulating normal and DDoS attack traffic for testing and analysis purposes.

#### To run:
1. Ensure that the required libraries are installed. You may need to install dependencies like `matplotlib`, `numpy`, `scipy`, etc.
2. Run the script using:
   ```bash
   python generate_and_plot_traffic.py
 ```
This will generate simulated traffic and plot the patterns for visualization.

3. 'manage_nacl_ip_rules_gui.py'
This script provides a graphical user interface (GUI) to manage IP rules in a Network Access Control List (NACL) for mitigating DDoS attacks by controlling incoming traffic.

To run:
Ensure that you have the necessary libraries installed (like tkinter for the GUI).

Execute the script with:

bash
Copy
Edit
python manage_nacl_ip_rules_gui.py
This will launch a GUI to manage and update IP filtering rules.
