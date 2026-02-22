
# Introduction to Honeypots & Cowrie

## 1. What is a Honeypot?

A **honeypot** is a deliberately vulnerable security tool or system intentionally exposed to the internet or internal network. Its primary purpose is to act as bait, attracting malicious actors and recording their actions without exposing actual production assets.

---

## 2. Primary Use Cases

Honeypots serve two major functions in cybersecurity:

* **Defensive Operations:** * **Early Warning System:** Alerts administrators of potential breaches or unauthorized network scanning.
    * **Decoy:** Distracts attackers, wasting their time and resources on fake infrastructure rather than targeting real, high-value assets.
* **Threat Intelligence & Research:**
    * **Data Collection:** Gathers real-time intelligence on the specific tools, tactics, and techniques (TTPs) adversaries are currently using in the wild.
    * **Defensive Engineering:** The recorded data is used to generate effective, up-to-date defensive measures (like new YARA rules, IDS signatures, or firewall blocks).

---

## 3. The Cowrie Honeypot Focus

In this specific scenario, we will be focusing on **Cowrie**, a widely used, medium-to-high interaction SSH and Telnet honeypot. 

**Key areas of upcoming analysis:**
* Viewing Cowrie from both the adversary's and the security researcher's perspective.
* Examining the specific types of data a Cowrie deployment collects.
* Applying analysis methodologies to the gathered data.
* Understanding what this data reveals about typical, automated botnet activity.

<img width="1024" height="559" alt="image" src="https://github.com/user-attachments/assets/0678c535-9fb3-488a-a38c-bf37e79bc760" />


# Honeypot Classification & Deployment

Honeypots are categorized primarily in two ways: by their level of **interactivity** (how "real" the system feels to an attacker) and their physical **deployment location** on the network.

---

## 1. Classification by Interactivity Level

The level of interactivity determines what an adversary can actually do once they connect to the honeypot.

| Level | Description & Capabilities | Examples |
| :--- | :--- | :--- |
| **Low-Interaction** | **The Facade.** Only simulates the bare minimum responses required by a specific service (e.g., an FTP banner). Attackers cannot access an operating system or perform "post-exploitation" activities. | `mailoney`, `dionaea` |
| **Medium-Interaction** | **The Simulation.** Emulates vulnerable services, the underlying OS, shell, and filesystem. Attackers can perform initial exploits and *some* post-exploitation commands, but because it is a simulation, complex actions will fail. | **`Cowrie`** (SSH/Telnet) |
| **High-Interaction** | **The Real Deal.** Fully functional systems (usually VMs) with deliberate vulnerabilities. Attackers can perform almost any action. These carry high risk; they must be tightly managed to prevent attackers from using them as a stepping stone into the real network. | Full VMs, or `Cowrie` acting as a proxy to a real VM. |

---

## 2. Classification by Deployment Location

Where a honeypot is placed dictates the type of threats it detects.

### Internal Honeypots
* **Location:** Deployed inside the local area network (LAN), behind the firewall.
* **Purpose:** To detect threats that have already breached the perimeter. This includes malicious insiders (trusted personnel) or external attackers who slipped past defenses via phishing or other means.
* **Significance:** An alert from an internal honeypot usually indicates a critical, active breach.

### External Honeypots
* **Location:** Deployed directly on the open internet, outside the LAN.
* **Purpose:** To monitor general attack trends from the wild.
* **Significance:** Because they are exposed, they are almost constantly under attack, collecting vast amounts of data on current tools and techniques used by botnets and indiscriminate attackers.
