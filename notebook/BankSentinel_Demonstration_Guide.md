# BankSentinel IDS — Demonstration & Presenter Guide

This guide breaks down the core features of the BankSentinel AI Intrusion Detection System. For each feature, you will find instructions on **How to Demo it** (what to click/show on screen) and **How to Explain it** (the narrative/talking points to use with your audience).

> [!NOTE]
> **Presenter Context**: BankSentinel uses a multi-agent AI architecture. For this demonstration, the traffic stream is driven by a background simulator that automatically injects background noise, simulated anomalies every 15 seconds, and a full Advanced Persistent Threat (APT) attack every 30 seconds.

---

## 1. The Live Alert Stream & Multi-Agent Correlation

The heart of the SOC Dashboard is the **Live Alert Feed**. 

- **How to Demo**: 
  1. Open the main dashboard and let the audience watch the live stream populate.
  2. Point out the alerts tagged `INFO` or `LOW` (background noise).
  3. Wait for the `CRITICAL`, `HIGH`, and `MEDIUM` alerts to flash onto the screen (happens every 30 seconds).
  4. Point out the alerts that have the gray tag: *Suppressed by deduplication* or *Suppressed by context_gating*.
  5. Point out the colored MITRE technique badges (e.g. `T1071.001`) that appear on the alerts.

- **How to Explain it**:
  > *"What you are seeing here is the live nervous system of our network. Most IDS platforms flood analysts with thousands of low-level alerts, causing 'alert fatigue'. BankSentinel solves this using our **Correlation Agent**. The Correlation Agent acts as the brain—it takes inputs from our Packet, Flow, and Behavior AI agents and fuses them into a single Composite Risk Score (CRS).* 
  > 
  > *Notice the suppressed alerts on the screen? The system is automatically deduplicating identical alerts, chaining related events together, and filtering out expected operational noise (like month-end batch processing). It maps everything automatically to the MITRE ATT&CK framework and only elevates true threats as HIGH or CRITICAL to the top of the queue."*

---

## 2. Automated Containment (The Response Agent)

BankSentinel doesn't just detect threats; it acts on them autonomously.

- **How to Demo**: 
  1. Draw attention to the feed when a red `CRITICAL` or orange `HIGH` alert appears.
  2. Explain that the CRITICAL alert represents a known Cobalt Strike beacon (an Advanced Persistent Threat).
  3. Point out the **"Actions Taken"** tags that immediately appear at the bottom of the CRITICAL alert card (e.g., *Host Quarantined*, *IP Blocked at Firewall*).

- **How to Explain it**:
  > *"In the banking sector, when a critical breach happens, human reaction time is simply too slow. Watch what happens when a CRITICAL alert hits the feed. Because the Composite Risk Score exceeded our threshold, it bypassed human review and triggered the **Response Agent**. Within milliseconds, the AI autonomously quarantined the infected source machine, blocked the destination IP at our edge firewall, and generated an incident report. It stops the bleeding instantly, allowing our human team to step in for forensics rather than firefighting."*

---

## 3. Live Threat Intelligence (TI) Integration

Even though the traffic is simulated, the AI's "knowledge" of threats is live.

- **How to Demo**: 
  1. Relate this back to the `CRITICAL` alert on the dashboard.
  2. Highlight that the AI matched an encrypted payload signature to a known malware family without decrypting the data.

- **How to Explain it**:
  > *"You might be wondering how the system recognized that Cobalt Strike attack so quickly without breaking TLS encryption. The Packet Agent is constantly pulling live Threat Intelligence feeds from global cybersecurity databases (like Abuse.ch) in the background. It checks encrypted traffic patterns—specifically JA3 TLS fingerprints—against these live blocklists. This means our AI is always armed with up-to-the-minute global threat data without us needing to manually update signatures."*

---

## 4. Cryptographic Audit Logs (Chain of Custody)

For Nepal Rastra Bank (NRB) compliance, automated actions must be strictly logged and tamper-proof.

- **How to Demo**: 
  1. Navigate to the **Compliance & Audit** page.
  2. Point out the table of recent actions (the action ledger).
  3. Notice the SHA-256 cryptographic hashes associated with each executed containment.

- **How to Explain it**:
  > *"When an AI is allowed to make automated containment decisions, we need absolute accountability for regulatory compliance. Every action taken by the Response Agent is written into an immutable database using a cryptographic SHA-256 hash chain—similar to how a blockchain works. If an attacker—or even a rogue administrator—tries to delete a log entry to cover their tracks, the hash chain will break. This mathematically proves to auditors that our incident logs have not been tampered with."*

---

## 5. NRB Compliance PDF Reporting

Regulatory reporting is a major administrative burden for financial SOC teams.

- **How to Demo**: 
  1. Stay on the **Compliance & Audit** page.
  2. Click the **Generate NRB Report** button.
  3. Point out the success notification and show the downloaded PDF report.
  4. Open the PDF to show the structured mapping to NRB and PCI-DSS compliance frameworks.

- **How to Explain it**:
  > *"Following a cyber incident, compiling the mandatory regulatory reports for the central bank can take hours or days. We built a one-click reporting feature that compiles the recent incident logs, the AI's explanation for why it took action, and the cryptographic proofs into a PDF formatted exactly to Nepal Rastra Bank's Cyber Security Framework guidelines. This turns a multi-day administrative headache into a one-click operation."*

---

## 6. System Health & KPIs

The dashboard provides real-time telemetry on the health of the AI agents.

- **How to Demo**: 
  1. Navigate back to the main dashboard.
  2. Point to the KPI cards at the very top of the dashboard.
  3. Highlight the "Active Agents" and "Suppressed Alerts" metrics.

- **How to Explain it**:
  > *"Finally, we give the SOC manager a bird's-eye view of the system's health. The top cards show us the average confidence score of our AI models, confirm that all independent AI agents are online and communicating, and quantify exactly how many false-positive alerts the Correlation Agent has suppressed today. It proves the ROI of the system in real-time by showing how much noise we are successfully filtering out."*

---

## 7. Red Team Adversary Simulation (Advanced Suppression Scenarios)

The **Red Team** page allows you to manually trigger pre-defined, complex attack chains to demonstrate the system's advanced suppression and correlation logic under stress.

- **How to Demo**:
  1. Navigate to the **Red Team** page using the sidebar.
  2. Explain the four available scenarios and launch them one by one.
  3. Point out the real-time feedback showing the total raw alerts generated versus the actual number of alerts emitted after suppression.
  4. Specifically highlight the **Ransomware Lateral Movement** scenario, showing how 22 raw alerts are collapsed down to just 2 emitted alerts.

- **How to Explain it**:
  > *"To truly understand how powerful the Correlation Agent is, we built a Red Team simulator that fires complex, multi-stage attacks at the pipeline. 
  >
  > For example, when we launch the **SWIFT C2 Beaconing** or **Insider Zero-Day** scenarios, you'll see the system catch 3 distinct, escalating stages of the attack. Because these are unique behaviors (initial access, lateral movement, and exfiltration), the system intelligently groups them into a single Campaign Ticket without suppressing any of them—ensuring the analyst gets the full story.
  >
  > However, look what happens when we launch the **Ransomware** scenario. Ransomware typically blasts out hundreds of identical RDP connection attempts to spread across the network, which normally floods a SOC with redundant alerts. Our causal-chaining engine instantly recognizes the pattern: it emits the initial compromise alert, automatically suppresses the 20 redundant propagation alerts, and emits the final encryption alert. It successfully reduces 22 raw alerts down to just 2, completely eliminating alert fatigue while still blocking the attack."*
