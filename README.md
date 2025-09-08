# SOC Automation Lab

<div align="center">

[![Security](https://img.shields.io/badge/Security-Operations-red.svg)](https://github.com)
[![Automation](https://img.shields.io/badge/SOAR-Enabled-blue.svg)](https://github.com)
[![Docker](https://img.shields.io/badge/Docker-Containerized-2496ED.svg)](https://github.com)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](https://github.com)
[![Status](https://img.shields.io/badge/Status-Production%20Ready-brightgreen.svg)](https://github.com)
[![Lab](https://img.shields.io/badge/Environment-Lab-orange.svg)](https://github.com)

</div>

---

## Table of Contents

- [Introduction](#introduction)
- [Architecture](#architecture)
- [Workflow](#workflow)
- [Component Documentation](#component-documentation)
- [Wazuh](#wazuh)
  - [Deployment](#deployment)
  - [Agents Setup](#agents-setup)
  - [File Integrity Monitoring (FIM)](#file-integrity-monitoring-fim-integration)
  - [Active Response (AR)](#active-response-ar)
  - [Suricata Integration](#suricata-integration)
- [MISP](#misp)
  - [Deployment](#deployment-1)
  - [Organization & Feeds](#organization--feeds)
  - [API Keys](#api-keys)
- [Suricata](#suricata)
  - [Installation](#installation)
  - [Configuration](#configuration)
  - [MISP Integration](#misp-integration-ioc-detection-rules)
- [Cortex & TheHive](#cortex--thehive)
  - [Deployment](#deployment-2)
  - [Cortex Setup](#cortex-setup)
  - [TheHive Setup](#thehive-setup)
- [Shuffle Workflow](#shuffle-workflow)
  - [Wazuh Webhook Integration](#wazuh-webhook-integration)
  - [Workflow Nodes](#workflow-nodes)
  - [Severity-based Branching](#severity-based-branching)

---

## Introduction

This project demonstrates a **fully integrated Security Operations Center (SOC)** environment with automated threat detection, enrichment, and response capabilities.... The lab showcases enterprise-grade security tools working in harmony to provide comprehensive threat detection and incident response...

### Integrated Technologies

| Component | Purpose | Role |
|-----------|---------|------|
| **Wazuh** | SIEM/EDR | Security monitoring and log analysis.... |
| **Suricata** | IDS/IPS | Network intrusion detection... |
| **MISP** | Threat Intelligence | IOC sharing and enrichment... |
| **TheHive & Cortex** | SOAR Platform | Incident response and analysis.... |
| **Shuffle** | Workflow Automation | Security orchestration... |

---

## Architecture

<div align="center">
<img width="1024" height="768" alt="SOC Architecture Diagram" src="https://github.com/user-attachments/assets/49088473-f8fe-4806-94f2-59707a2d9f1a" />
</div>

---

## Workflow

<div align="center">
<img width="1024" height="768" alt="Security Workflow Flowchart" src="https://github.com/user-attachments/assets/1d7a4cc0-fbc4-4c9e-93be-996be5dd2ab3" />
</div>

---

## Component Documentation

<div align="center">
<p>
  <a href="#wazuh">
    <img src="assets/logos/wazuh.png" alt="Wazuh Documentation" height="60"/>
  </a>
  <a href="#misp">
    <img src="assets/logos/misp.png" alt="MISP Documentation" height="60"/>
  </a>
  <a href="#suricata">
    <img src="assets/logos/suricata.png" alt="Suricata Documentation" height="60"/>
  </a>
  <a href="#cortex--thehive">
    <img src="assets/logos/thehive.png" alt="TheHive & Cortex Documentation" height="60"/>
  </a>
  <a href="#shuffle-workflow">
    <img src="assets/logos/shuffle.png" alt="Shuffle Documentation" height="60"/>
  </a>
</p>
</div>

---

## Wazuh

[![SIEM](https://img.shields.io/badge/Type-SIEM%2FEDR-blue.svg)](https://wazuh.com)
[![Docker](https://img.shields.io/badge/Deployment-Docker-2496ED.svg)](https://wazuh.com)

### Deployment

The Wazuh deployment follows the official [Docker Deployment Guide](https://documentation.wazuh.com/current/deployment-options/docker/wazuh-container.html) using single-node mode for optimal performance in lab environments....

**Access Information:**
- **URL:** `https://<server-ip-address>`
- **Default Credentials:** `admin:SecretPassword`

> **Security Notice:** Change default credentials immediately after deployment....

<div align="center">
<img width="1720" height="860" alt="Wazuh Dashboard" src="https://github.com/user-attachments/assets/1b1b7232-12bd-4b54-ae6c-7f8c842bb404" />
</div>

### Agents Setup

**Step-by-step Agent Configuration:**

1. Navigate to **Agents Management → Summary → Deploy New Agents**
2. Select your operating system and architecture (e.g., Debian amd64 for Ubuntu)....
3. Configure the agent's IP address...

<div align="center">
<img width="1789" height="895" alt="Agent Deployment Interface" src="https://github.com/user-attachments/assets/9cdeb3b9-b565-4017-a5d6-0932521d5e70" />
</div>

4. Execute the provided CLI commands on your target system....
5. Verify agent registration in the **Agents Summary**...

<div align="center">
<img width="1920" height="730" alt="Active Wazuh Agents" src="https://github.com/user-attachments/assets/976368ae-82a4-4008-97b7-a2792c4d80fd" />
</div>

**Additional Resources:** [Comprehensive Agent Installation Guide](https://documentation.wazuh.com/current/installation-guide/wazuh-agent/index.html)

### File Integrity Monitoring (FIM) Integration

[![Monitoring](https://img.shields.io/badge/Feature-FIM-green.svg)](https://wazuh.com)

**Configuration Steps:**

1. **Edit Configuration File:**
   ```bash
   /var/ossec/etc/ossec.conf
   ```

2. **Locate and Configure FIM Block:**
   - Review the `<fim>` section....
   - Add monitored directories with `realtime` parameter for instant detection...

<div align="center">
<img width="1881" height="940" alt="FIM Configuration Block" src="https://github.com/user-attachments/assets/ae97da47-374c-4c0b-9182-013ca280856b" />
</div>

3. **Monitor FIM Activity:**
   - Navigate to **Endpoint Security → File Integrity Monitoring**....
   - Use **Explore Agent** for detailed dashboard, inventory, and event analysis...

<div align="center">
<img width="1739" height="869" alt="FIM Monitoring Dashboard" src="https://github.com/user-attachments/assets/c0a10c56-91a3-4ba4-99bf-8bf3c2ec718a" />
</div>

### Active Response (AR)

[![Response](https://img.shields.io/badge/Feature-Active%20Response-red.svg)](https://wazuh.com)

This lab demonstrates Wazuh's Active Response using the `firewall-drop` command for automated threat mitigation....

<div align="center">
<img width="1920" height="601" alt="Firewall Drop Command Configuration" src="https://github.com/user-attachments/assets/b48f86cd-f04e-4fc9-b5b5-7a06733b29ef" />
</div>

**Configuration Process:**

1. **Edit ossec.conf** and locate `<active-response>` section...
2. **Add firewall-drop block** to enable automated blocking....

<div align="center">
<img width="1920" height="246" alt="Active Response Configuration" src="https://github.com/user-attachments/assets/5dfd977e-a47a-4789-8c63-461675db98e8" />
</div>

**Reference:** [Complete Active Response Documentation](https://documentation.wazuh.com/current/user-manual/capabilities/active-response/index.html)

### Suricata Integration

[![Integration](https://img.shields.io/badge/Integration-Suricata-orange.svg)](https://suricata.io)

> **Prerequisites:** Complete Suricata deployment and note log directory path (typically `/var/log/suricata`)....

**Integration Configuration:**

Add the following block to `ossec.conf` under the `localfiles` section:

```xml
<!-- Suricata Integration Block -->
<localfile>
  <log_format>json</log_format>
  <location>/var/log/suricata/eve.json</location>
</localfile>
```

**Verification:**
Access Suricata logs through **Explore → Discover** to confirm integration:

<div align="center">
<img width="1920" height="666" alt="Suricata Integration Logs" src="https://github.com/user-attachments/assets/2c5d45fe-bf78-4811-8630-609ee8a4655f" />
</div>

---

## MISP

[![TIP](https://img.shields.io/badge/Type-Threat%20Intelligence-purple.svg)](https://misp-project.org)
[![Docker](https://img.shields.io/badge/Deployment-Docker-2496ED.svg)](https://misp-project.org)

### Deployment

MISP deployment utilizes the official [MISP Docker Repository](https://github.com/MISP/misp-docker) for containerized threat intelligence platform....

**Pre-deployment Configuration:**
- Modify port mapping in `docker-compose.yml` to avoid conflicts....
- Update `misp-core` service port configuration...

<div align="center">
<img width="1670" height="835" alt="MISP Core Configuration" src="https://github.com/user-attachments/assets/5d4da18b-14ff-4615-8c84-97ba9115a3f0" />
</div>

**Deployment Command:**
```bash
docker-compose up -d
```

**Access Information:**
- **URL:** `https://<server-ip>:8443`
- **Default Credentials:** `admin@admin.test:admin`

> **Security Notice:** Update default credentials immediately....

<div align="center">
<img width="1593" height="797" alt="MISP Web Interface" src="https://github.com/user-attachments/assets/c92c4bc2-2ea1-4eee-b460-a8da99d6730b" />
</div>

### Organization & Feeds

[![Feeds](https://img.shields.io/badge/Feature-Threat%20Feeds-yellow.svg)](https://misp-project.org)

**Initial Setup:**
1. **Create Organization** - Establish your security organization profile....
2. **Configure Feeds** - Navigate to **Sync Actions → Feeds**...
3. **Enable Threat Feeds** - Use **Load Default Feed Metadata** and activate desired feeds....

<div align="center">
<img width="1712" height="856" alt="Enabled Threat Intelligence Feeds" src="https://github.com/user-attachments/assets/e818ab92-9779-4d7a-b731-bb0b6287df39" />
</div>

**Feed Monitoring:**
All threat intelligence events are accessible via the **Home** tab:

<div align="center">
<img width="1782" height="891" alt="Threat Intelligence Events Dashboard" src="https://github.com/user-attachments/assets/207cdbb6-569c-4938-b6b5-8bdacf6a1ad5" />
</div>

### API Keys

[![API](https://img.shields.io/badge/Feature-API%20Integration-lightblue.svg)](https://misp-project.org)

**Integration Requirements:**
Generate API keys for external integrations (Suricata, TheHive):

1. Navigate to **Admin → Auth Keys**....
2. Generate integration-specific keys...
3. **Important:** Document keys immediately - they're only visible once....

---

## Suricata

[![IDS](https://img.shields.io/badge/Type-IDS%2FIPS-darkgreen.svg)](https://suricata.io)
[![Network](https://img.shields.io/badge/Layer-Network-blue.svg)](https://suricata.io)

### Installation

**Ubuntu Installation via Official PPA:**

```bash
sudo apt-get install software-properties-common
sudo add-apt-repository ppa:oisf/suricata-stable
sudo apt-get update
sudo apt-get install suricata
```

### Configuration

[![Config](https://img.shields.io/badge/Step-Configuration-orange.svg)](https://suricata.io)

**Network Interface Setup:**

1. **Identify WAN Interface:**
   ```bash
   ip addr
   ```
   <div align="center">
   <img width="1156" height="85" alt="Network Interface Identification" src="https://github.com/user-attachments/assets/7f949461-d544-49e7-948e-af69d7398453" />
   </div>

2. **Configure Suricata (`/etc/suricata/suricata.yaml`):**
   
   **Update Monitored Interface:**
   <div align="center">
   <img width="796" height="50" alt="AF-Packet Interface Configuration" src="https://github.com/user-attachments/assets/cc72c362-ceee-4b7e-a0a5-6a64dc785c8b" />
   </div>
   
   **Set Home Network Range:**
   <div align="center">
   <img width="1673" height="136" alt="Home Network Configuration" src="https://github.com/user-attachments/assets/6302333a-5bfc-4bed-8d70-73d0a62c7a04" />
   </div>

### MISP Integration (IOC Detection Rules)

[![IOC](https://img.shields.io/badge/Feature-IOC%20Detection-red.svg)](https://suricata.io)

Suricata integrates with MISP to leverage threat intelligence for proactive IOC detection....

**Rule Export Options:**
MISP provides multiple export formats accessible via **Home → Export**:

<div align="center">
<img width="1920" height="772" alt="MISP Rule Export Options" src="https://github.com/user-attachments/assets/89fdba6b-8f63-486a-b189-47043a5e63c3" />
</div>

**API-based Rule Import:**
```bash
curl -k -H "Authorization: <MISP_API_KEY>" \
     -H "Accept: application/json" \
     <MISP_IP>/attributes/text/download/suricata \
     -o /var/lib/suricata/rules/<filename>
```

**Rule Processing Challenges:**
Many MISP rules require preprocessing for Suricata compatibility.... A custom Python sanitization script was developed to address format inconsistencies:

- **Input:** `misp.rules` (raw MISP export)....
- **Output:** `misp_clean.rules` (Suricata-compatible format)...

<div align="center">
<img width="1842" height="221" alt="Rule Loading Process" src="https://github.com/user-attachments/assets/dd431f3f-5cd9-491a-922c-1c60e684142f" />
</div>

**Sanitized Rule Validation:**
<div align="center">
<img width="1920" height="981" alt="Validated Suricata Rules" src="https://github.com/user-attachments/assets/63fe58d4-82fa-4760-b9cf-91450b8a5a3f" />
</div>

**Source Verification:**
```bash
suricata-update list-enabled-sources
```

<div align="center">
<img width="1395" height="161" alt="Enabled Rule Sources" src="https://github.com/user-attachments/assets/949fd451-6333-4e74-96b4-0be474544dda" />
</div>

**Detection Testing:**
Monitor detection effectiveness by tailing alert logs:
```bash
tail -f /var/log/suricata/fast.log
```

<div align="center">
<img width="1920" height="606" alt="Suricata Detection Logs" src="https://github.com/user-attachments/assets/9509c861-d59d-4de4-860d-94138242bf22" />
</div>

**Wazuh Integration Verification:**
Suricata alerts are automatically ingested by Wazuh:

<div align="center">
<img width="1509" height="793" alt="Suricata Alerts in Wazuh" src="https://github.com/user-attachments/assets/a081e29d-0357-47b3-ad35-12d27ac2f100" />
</div>

---

## Cortex & TheHive

[![SOAR](https://img.shields.io/badge/Type-SOAR%20Platform-indigo.svg)](https://thehive-project.org)
[![Incident](https://img.shields.io/badge/Purpose-Incident%20Response-red.svg)](https://thehive-project.org)

### Deployment

Deployment utilizes StrangeBee's testing environment profile for rapid lab setup....

**Repository:** [StrangeBee Docker Testing Environment](https://github.com/StrangeBeeCorp/docker/tree/main/testing)

**Configuration Changes:**
- **Nginx Port Mapping:** Modified to `7443:443` to prevent conflicts...

**Access URLs:**
- **Cortex:** `https://<ip>:7443/cortex`
- **TheHive:** `https://<ip>:7443/thehive`

> **Security Notice:** Change default credentials immediately after deployment....

### Cortex Setup

[![Analyzers](https://img.shields.io/badge/Feature-Analyzers-green.svg)](https://cortexneurons.org)

**Initial Configuration:**

1. **Database Setup** - Configure first-time user credentials:
   
   <div align="center">
   <img width="1724" height="862" alt="Cortex Initial Setup" src="https://github.com/user-attachments/assets/5facfe44-a6de-4545-acdf-503ffbcbb021" />
   </div>

2. **Organization Management:**
   - Create your security organization....
   - Configure organization users with appropriate permissions...
   
   <div align="center">
   <img width="1920" height="547" alt="Cortex Organization Setup" src="https://github.com/user-attachments/assets/1bbd6262-4340-4475-a3d7-1448a0baab7d" />
   </div>

3. **Analyzers & Responders Configuration:**
   
   > **Note:** Available only after organization user login....
   
   - Navigate to **Organization → Analyzers**...
   - Enable required analyzers for threat analysis....
   
   <div align="center">
   <img width="1920" height="242" alt="Analyzer Configuration Tab" src="https://github.com/user-attachments/assets/fe6098c9-8bf5-45f4-bffe-e7ce8f2bfecb" />
   </div>
   
   - **API Key Requirements:** Most analyzers require service-specific API keys....
   - **Verification:** Enabled analyzers appear in the main Analyzers tab...
   
   <div align="center">
   <img width="1920" height="696" alt="Active Cortex Analyzers" src="https://github.com/user-attachments/assets/598e6411-a902-45e7-b491-29676a0282aa" />
   </div>

4. **API Key Management:**
   - Document **OrgAdmin API key** for MISP and Shuffle integrations....

### TheHive Setup

[![Cases](https://img.shields.io/badge/Feature-Case%20Management-blue.svg)](https://thehive-project.org)

**Initial Access:**
- **Email:** `admin@thehive.local`
- **Password:** `secret`

**Configuration Steps:**

1. **Organization Setup** - Create your incident response organizations....

2. **Connector Configuration:**
   - Navigate to **Platform Management → Connectors**...
   - Configure **Cortex** and **MISP** server connections....
   - Provide URLs and API keys for each service...
   - Use **"Check connection"** to validate integrations....
   
3. **Integration Verification:**
   - Successful connections visible under **License** tab with server statistics...
   
   <div align="center">
   <img width="1920" height="764" alt="TheHive License and Integration Status" src="https://github.com/user-attachments/assets/030dd431-9af8-4a2b-acb4-63967cfe2bad" />
   </div>

4. **API Key Generation:**
   - Access **Account Settings → API Key**....
   - Generate and document organization user API key for Shuffle integration...

5. **Server Status Monitoring:**
   - Click the **Cortex icon** to view configured servers....
   
   <div align="center">
   <img width="1230" height="653" alt="Configured Cortex Servers" src="https://github.com/user-attachments/assets/38865937-3a0f-4cce-957c-844de6750646" />
   </div>

---

## Shuffle Workflow

[![Orchestration](https://img.shields.io/badge/Type-Security%20Orchestration-purple.svg)](https://shuffler.io)
[![Automation](https://img.shields.io/badge/Feature-Automation-brightgreen.svg)](https://shuffler.io)

The implemented automation workflow follows the logic illustrated in the project flowchart, providing end-to-end security orchestration....

### Wazuh Webhook Integration

[![Webhook](https://img.shields.io/badge/Trigger-Webhook-orange.svg)](https://shuffler.io)

**Webhook Configuration:**
- Workflow initiates via webhook URL integrated into Wazuh's `ossec.conf`....
- **Challenge:** Self-signed certificate authorization failures...

**Certificate Trust Resolution:**

1. **Export Shuffle Certificate:**
   ```bash
   openssl s_client -connect "$SHUFFLE_ADDR" -showcerts </dev/null 2>/dev/null \
     | openssl x509 -outform PEM > shuffle-ca.crt
   ```

2. **Verification Check:**
   ```bash
   head -n 2 shuffle-ca.crt   # Should display: -----BEGIN CERTIFICATE-----
   ```

3. **Install Certificate in Wazuh Manager:**
   ```bash
   docker cp shuffle-ca.crt "$MANAGER":/etc/pki/ca-trust/source/anchors/shuffle-ca.crt
   ```

4. **Update CA Tools:**
   ```bash
   docker exec "$MANAGER" sh -c 'command -v yum >/dev/null && yum -y install ca-certificates || true'
   ```

5. **Rebuild CA Bundle:**
   ```bash
   docker exec "$MANAGER" update-ca-trust extract
   ```

6. **Validate Certificate Trust:**
   ```bash
   docker exec "$MANAGER" \
     openssl s_client -connect "$SHUFFLE_ADDR" -CAfile /etc/ssl/certs/ca-bundle.crt </dev/null \
     | sed -n '/Verify return code/,$p'   # Should return: "Verify return code: 0 (ok)..."
   ```

**Result:** Wazuh alerts successfully flow to Shuffle workflow....

### Workflow Nodes

[![Parsing](https://img.shields.io/badge/Step-IOC%20Parsing-yellow.svg)](https://shuffler.io)

**1. Webhook → Parse IOCs Node**
- Successfully extracts IPs and file hashes from security events....

<div align="center">
<img width="1501" height="863" alt="IOC Parsing Workflow" src="https://github.com/user-attachments/assets/b26ffbe1-340a-4a80-beb3-73a726795a59" />
</div>

**2. TheHive Alert Creation → Conditional Observable Addition**

[![Observables](https://img.shields.io/badge/Feature-Observables-lightgreen.svg)](https://shuffler.io)

**Branch Conditions:**
- **Hash Detection:** Logs containing `syscheck` (FIM events)...
- **IP Detection:** Logs containing `journald` (system events)....

**FIM Alert with Linked Observables:**
<div align="center">
<img width="1405" height="338" alt="FIM Alert with IOCs" src="https://github.com/user-attachments/assets/5311bb9a-d7a5-48ac-93c9-a16cf60ca5dd" />
</div>

**Hash-based Alert Example:**
<div align="center">
<img width="1490" height="621" alt="Hash Detection Alert" src="https://github.com/user-attachments/assets/1389deb9-8273-43f6-8873-317988e89926" />
</div>

**Observable Linking:**
<div align="center">
<img width="1173" height="608" alt="Linked Hash Observables" src="https://github.com/user-attachments/assets/c0ad37a5-8fa8-414f-8c68-96a1f5fb9613" />
</div>

**3. Cortex Analysis Chain:**

[![Analysis](https://img.shields.io/badge/Stage-Analysis-blue.svg)](https://shuffler.io)

**Get Available Analyzers:**
<div align="center">
<img width="1511" height="894" alt="Available Analyzers Query" src="https://github.com/user-attachments/assets/784c65c6-07ea-4cb5-9764-fbbcb1459bb9" />
</div>

**Execute Analyzers:**
<div align="center">
<img width="1495" height="875" alt="Analyzer Execution Results" src="https://github.com/user-attachments/assets/07b7bb12-fbbd-4143-a633-05b08e16e117" />
</div>

**4. Maliciousness Filter Node:**
- **Non-malicious IOCs:** Workflow terminates....
- **Malicious IOCs:** Workflow continues to response phase...

**5. Alert Enrichment:**
Updates TheHive alerts with analyzer intelligence:

<div align="center">
<img width="1496" height="845" alt="Alert Update with Analyzer Results" src="https://github.com/user-attachments/assets/9388aa75-be72-4511-8cac-16312cd279fa" />
</div>

**Enriched Alert with Intelligence Tags:**
<div align="center">
<img width="1920" height="843" alt="Intelligence-Enriched Alert" src="https://github.com/user-attachments/assets/37e7ed65-64ef-4644-b409-e6d05632930e" />
</div>

### Severity-based Branching

[![Response](https://img.shields.io/badge/Stage-Automated%20Response-red.svg)](https://shuffler.io)

**Automated Response Logic:**

**Low-Medium Severity (< 6): Wazuh Active Response**

[![Low Severity](https://img.shields.io/badge/Severity-Low%2FMedium-yellow.svg)](https://shuffler.io)

1. **API Token Acquisition:**
   <div align="center">
   <img width="1502" height="891" alt="Wazuh API Token Request" src="https://github.com/user-attachments/assets/a7d5a453-933e-401e-ba4b-183bbfd68c67" />
   </div>

2. **Active Response Execution:**
   <div align="center">
   <img width="1507" height="882" alt="Automated Active Response" src="https://github.com/user-attachments/assets/ead4265c-93bf-4456-9c4b-78156936d65a" />
   </div>

**High Severity (≥ 6): Case Creation & Analyst Review**

[![High Severity](https://img.shields.io/badge/Severity-High%2FCritical-red.svg)](https://shuffler.io)

1. **TheHive Case Creation:**
   <div align="center">
   <img width="1492" height="878" alt="High Severity Case Creation" src="https://github.com/user-attachments/assets/31e43471-a047-43c1-8032-5e5e0a85aafb" />
   </div>

2. **Linked Alert Management:**
   <div align="center">
   <img width="1920" height="849" alt="Cases with Linked Alerts" src="https://github.com/user-attachments/assets/6e52b675-2a01-49a5-a69c-74bb523d4a45" />
   </div>

   <div align="center">
   <img width="1920" height="827" alt="Detailed Linked Alert View" src="https://github.com/user-attachments/assets/0ec09b85-0493-44da-9494-b94ae03f2852" />
   </div>

3. **Artifact Analysis:**
   <div align="center">
   <img width="1507" height="893" alt="Case Artifact Retrieval" src="https://github.com/user-attachments/assets/b6078a1c-9a62-478f-aceb-4aa283eeb673" />
   </div>

4. **In-App Analyzer Automated Execution:**
    The Analayzers resport will be available in Thehive case for speedy analyst review...
   <div align="center">
   <img width="1493" height="888" alt="Screenshot (586)" src="https://github.com/user-attachments/assets/0a8d5ae8-7275-4acf-8e9b-efa4e1be2d60" />
    <div/>
     <div align="center">
   <img width="1920" height="769" alt="Screenshot (589)" src="https://github.com/user-attachments/assets/3dda74f9-6b59-47ec-8026-1fe681934b42" />
    <div/>
   <div align="center">
   <img width="1920" height="856" alt="In-App Security Analysis" src="https://github.com/user-attachments/assets/6238d485-b613-4300-b95b-b27375707c3e" />
   </div>

---

<div align="center">

## Lab Complete

[![Complete](https://img.shields.io/badge/Status-Complete-brightgreen.svg)](https://github.com)
[![Functional](https://img.shields.io/badge/State-Fully%20Functional-success.svg)](https://github.com)

**This SOC Automation Lab demonstrates enterprise-grade security orchestration with:**
- Automated threat detection and analysis....
- Intelligence-driven response workflows...  
- Seamless tool integration and data flow....
- Severity-based incident escalation...
- Complete audit trail and case management....

---

[![Next](https://img.shields.io/badge/Phase-Next%20Steps-blue.svg)](https://github.com)

**Next Steps:**
- Customize detection rules for your environment....
- Implement additional analyzer modules...
- Enhance workflow automation logic....
- Scale deployment for production use...

</div>
  
