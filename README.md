# SOC Automation Lab

## Introduction
This project demonstrates a fully integrated Security Operations Center (SOC) environment with **automated threat detection, enrichment, and response**.  
It integrates:
- **Wazuh** (SIEM/EDR)
- **Suricata** (IDS/IPS)
- **MISP** (Threat Intelligence Sharing)
- **TheHive & Cortex** (Incident Response & Analysis)
- **Shuffle** (SOAR Automation)

---

## Architecture
<img width="1024" height="768" alt="2" src="https://github.com/user-attachments/assets/49088473-f8fe-4806-94f2-59707a2d9f1a" />


## Workflow Flowchart
<img width="1024" height="768" alt="1" src="https://github.com/user-attachments/assets/1d7a4cc0-fbc4-4c9e-93be-996be5dd2ab3" />



---

## Contents

<p align="center">
  <a href="docs/wazuh.md">
    <img src="assets/logos/wazuh.png" alt="Wazuh" height="60"/>
  </a>
  <a href="docs/misp.md">
    <img src="assets/logos/misp.png" alt="MISP" height="60"/>
  </a>
  <a href="docs/suricata.md">
    <img src="assets/logos/suricata.png" alt="Suricata" height="60"/>
  </a>
  <a href="docs/thehive-cortex.md">
    <img src="assets/logos/thehive.png" alt="TheHive & Cortex" height="60"/>
  </a>
  <a href="docs/shuffle.md">
    <img src="assets/logos/shuffle.png" alt="Shuffle" height="60"/>
  </a>
</p>
 
## Wazuh

### Deployment

For Docker deployment of Wazuh, the guide [Wazuh Docker Deployment](https://documentation.wazuh.com/current/deployment-options/docker/wazuh-container.html) was followed.  
Wazuh was deployed in **single-node mode**. After deployment, you can access the UI at: https://<server-ip-address>


**Default login:** `admin:SecretPassword`  
**DON'T FORGET TO CHANGE THE LOGIN DEFAULT CREDENTIALS**
<img width="1720" height="860" alt="wazuh-ui" src="https://github.com/user-attachments/assets/1b1b7232-12bd-4b54-ae6c-7f8c842bb404" />


---

### Agents Setup

1. Go to **Agents Management → Summary → Deploy New Agents**.  
2. Choose the OS and corresponding architecture (Debian amd64 for Ubuntu server in this case).  
3. Enter the IP address of the agent.  

<img width="1789" height="895" alt="agent-page" src="https://github.com/user-attachments/assets/9cdeb3b9-b565-4017-a5d6-0932521d5e70" />


4. You will be presented with a series of commands to run on your agent's CLI.  
5. After executing the commands, the agent should appear in your **Agents Summary** list.  

<img width="1920" height="730" alt="wazuh-agent" src="https://github.com/user-attachments/assets/976368ae-82a4-4008-97b7-a2792c4d80fd" />


For a more comprehensive guide, refer to the [Wazuh Agent Installation Guide](https://documentation.wazuh.com/current/installation-guide/wazuh-agent/index.html).

---

### File Integrity Monitoring (FIM) Integration

1. Access the configuration file:
/var/ossec/etc/ossec.conf

2. Locate the `<fim>` block and review or modify as desired.  
3. In this project, a folder was added to simulate FIM alerts, with the `realtime` parameter for instantaneous detection.

<img width="1881" height="940" alt="fim-block" src="https://github.com/user-attachments/assets/ae97da47-374c-4c0b-9182-013ca280856b" />


4. To check FIM activity on agents, navigate to **Endpoint Security → File Integrity Monitoring**.  
5. Select a specific agent via **Explore Agent** to view **Dashboard, Inventory, and Events** for detailed information.

<img width="1739" height="869" alt="fim-page" src="https://github.com/user-attachments/assets/c0a10c56-91a3-4ba4-99bf-8bf3c2ec718a" />


---

### Active Response (AR)

For this lab, Wazuh's AR feature is demonstrated using the `firewall-drop` command.
<img width="1920" height="601" alt="firewall-drop-command-block" src="https://github.com/user-attachments/assets/b48f86cd-f04e-4fc9-b5b5-7a06733b29ef" />

1. Open `ossec.conf` and locate the `<active-response>` section.  
2. Add a block for the `firewall-drop` command to enable it.

<img width="1920" height="246" alt="active-response-block" src="https://github.com/user-attachments/assets/5dfd977e-a47a-4789-8c63-461675db98e8" />


Wazuh’s documentation for Active Response is comprehensive and can be found [here](https://documentation.wazuh.com/current/user-manual/capabilities/active-response/index.html).


---
### Suricata integration
> **Note:** This step should be attempted after deploying suricata and noting down its log directory, in my case it was /var/log/suricata, but you should check that it is in /etc/suricata/suricata.yaml

in ossec.conf, add the following block under the localfiles section to enable the suricata integration: 
```bash
<!-- Add this new block for Suricata -->
  <localfile>
    <log_format>json</log_format> <!-- #> ... Tells Wazuh to parse each line as a JSON object -->
    <location>/var/log/suricata/eve.json</location> <!-- #> again, must match the path in suricata.yaml -->
  </localfile>

```
Then we can view suricata logs from explore -> discover. We can see that the log location is the log directory we configured in the ossec file  
<img width="1920" height="666" alt="suricata-integration" src="https://github.com/user-attachments/assets/2c5d45fe-bf78-4811-8630-609ee8a4655f" />

---

## MISP

### Deployment

MISP was deployed using Docker via the repository: [MISP Docker](https://github.com/MISP/misp-docker).  

> **Note:** Before running `docker-compose up`, adjust the **port mapping** for `misp-core` in the `docker-compose.yml` file to avoid conflicts.  

<img width="1670" height="835" alt="misp-core" src="https://github.com/user-attachments/assets/5d4da18b-14ff-4615-8c84-97ba9115a3f0" />


Start the containers:
docker-compose up -d

Access the MISP web interface at:
https://<server-ip>:8443
> **Note:** Default login: `admin@admin.test:admin.`
**DON'T FORGET TO CHANGE THE LOGIN DEFAULT CREDENTIALS**
<img width="1593" height="797" alt="misp-ui" src="https://github.com/user-attachments/assets/c92c4bc2-2ea1-4eee-b460-a8da99d6730b" />


### Organization & Feeds

Create your own organization in MISP.

Navigate to Sync Actions → Feeds.

Add new feeds or enable one of the default feeds by clicking Load Default Feed Metadata, then enable the desired feeds.
<img width="1712" height="856" alt="enabled-feeds" src="https://github.com/user-attachments/assets/e818ab92-9779-4d7a-b731-bb0b6287df39" />

All feed events are visible on the Home tab.
<img width="1782" height="891" alt="events-screen" src="https://github.com/user-attachments/assets/207cdbb6-569c-4938-b6b5-8bdacf6a1ad5" />

### API Keys

For workflow integrations (e.g., Suricata and TheHive), create API keys:

Go to Admin → Auth Keys.

Generate new keys for each integration.

Important: Note the keys immediately after creation.... they are only visible once.

----
# Suricata Setup & Integration

## Installation

Install Suricata on Ubuntu using the official stable PPA:

```bash
sudo apt-get install software-properties-common
sudo add-apt-repository ppa:oisf/suricata-stable
sudo apt-get update
sudo apt-get install suricata
```
## Configuration

-Check your WAN IP with: $ip addr 
<img width="1156" height="85" alt="ip-add" src="https://github.com/user-attachments/assets/7f949461-d544-49e7-948e-af69d7398453" />

-Then edit the main Suricata configuration file (/etc/suricata/suricata.yaml) with your preferred editor to: 
  1- Update the monitored interface under af-packet.
<img width="796" height="50" alt="af-packet-int" src="https://github.com/user-attachments/assets/cc72c362-ceee-4b7e-a0a5-6a64dc785c8b" />

  2- Set your home network for accurate alerting.
<img width="1673" height="136" alt="home-net" src="https://github.com/user-attachments/assets/6302333a-5bfc-4bed-8d70-73d0a62c7a04" />


## MISP Integration (IOC Detection Rules)

In this workflow, Suricata acts as an IDS integrated with MISP to detect IOCs.
MISP provides rule files compatible with IDS/IPS platforms like Snort and Suricata.. the rules can be accessed via API or, for testing purposes, by downloading the rule file from Misp, you can go to home -> export to see the available options
<img width="1920" height="772" alt="misp-nids" src="https://github.com/user-attachments/assets/89fdba6b-8f63-486a-b189-47043a5e63c3" />

### Importing Rules

Download rules from MISP and save them in Suricata’s rules directory:
```BASH
curl -k -H "Authorization: <MISP_API_KEY>" \
     -H "Accept: application/json" \
     <MISP_IP>/attributes/text/download/suricata \
     -o /var/lib/suricata/rules/<filename>
```
### Rule Parsing Issues

Many rules from MISP fail to parse in Suricata due to format inconsistencies...
A custom Python script was written to clean and validate the rules:
-Input: misp.rules (via curl)
-Output: misp_clean.rules
Multiple iterations were required to ensure all rules passed parsing (as you can see from the script filename, v6, we really went through it...)
<img width="1842" height="221" alt="role-loading" src="https://github.com/user-attachments/assets/dd431f3f-5cd9-491a-922c-1c60e684142f" />
viewing the first few lines of the sanitized rules to see that they're in the appropriate syntax for suricata: <img width="1920" height="981" alt="Screenshot (648)" src="https://github.com/user-attachments/assets/63fe58d4-82fa-4760-b9cf-91450b8a5a3f" />

The sources for suricata rules can be cheked by 
```bash 
suricata-update list-enabled-sources
```
We can see misp is listed as a source after the successful synchronization:
<img width="1395" height="161" alt="Screenshot (642)" src="https://github.com/user-attachments/assets/949fd451-6333-4e74-96b4-0be474544dda" />

### Testing Detection

After loading the cleaned rules, test detection by triggering a MISP rule and then tailing Suricata logs alerts in /var/log/suricata/fast.log.
<img width="1920" height="606" alt="misp-log" src="https://github.com/user-attachments/assets/9509c861-d59d-4de4-860d-94138242bf22" />

Alerts are also visible in Wazuh after the Suricata-Wazuh integration (see Wazuh section for details)...
<img width="1509" height="793" alt="misp-log-in-wazuh" src="https://github.com/user-attachments/assets/a081e29d-0357-47b3-ad35-12d27ac2f100" />

----

# Cortex & TheHive Setup Guide

## Deployment
Cortex and TheHive were deployed using the **testing environment** deployment profile from StrangeBee:  
🔗 [StrangeBee Docker Repository](https://github.com/StrangeBeeCorp/docker/tree/main/testing)

- The **nginx port mapping** was changed to `7443:443` to avoid conflicts with Wazuh and MISP.
- Access URLs:  
  - Cortex → `https://<ip>:7443/cortex`  
  - TheHive → `https://<ip>:7443/thehive`
**DON'T FORGET TO CHANGE THE LOGIN DEFAULT CREDENTIALS**
---

## Cortex Setup
1. On first access, you’ll be asked to **set the database** (configure the first user login credentials).
   <img width="1724" height="862" alt="cortex-ui" src="https://github.com/user-attachments/assets/5facfe44-a6de-4545-acdf-503ffbcbb021" />

   - After creating the initial username and password, log in to create:
     - Your organization  
     - An organization user with the proper permissions  
      <img width="1920" height="547" alt="cortex-org" src="https://github.com/user-attachments/assets/1bbd6262-4340-4475-a3d7-1448a0baab7d" />

3. **Analyzers & Responders**  
   - These can only be configured **after logging in with your organization user account**.  
   - Go to **Organization > Analyzers** and enable the desired analyzers.
     <img width="1920" height="242" alt="analyzers-tab" src="https://github.com/user-attachments/assets/fe6098c9-8bf5-45f4-bffe-e7ce8f2bfecb" />
 
   - Most analyzers require an **API key** (obtainable by signing up on the analyzer’s respective website).  
   - Once enabled, analyzers will appear under the **Analyzers tab** (uppermost menu).  
<img width="1920" height="696" alt="cortex analyzers" src="https://github.com/user-attachments/assets/598e6411-a902-45e7-b491-29676a0282aa" />

4. **Save Org Admin API Key**  
   - Note down the **OrgAdmin’s API key** for later use in **MISP** and **Shuffle integrations**.

---

## TheHive Setup
1. Default login credentials:  
   - **Email:** `admin@thehive.local`  
   - **Password:** `secret`  

2. After logging in, create your organizations.

3. **Configure Connectors**  
   - Go to: **Platform Management > Connectors**  
   - Configure servers under the **Cortex** and **MISP** tabs.  
   - Each requires the **URL** and **API key** of the service.  
   - Use the **"Check connection"** button to test connectivity before enabling.  
   - Successful integrations can be confirmed under the **License tab** (server stats visible).     <img width="1920" height="764" alt="thehice license tab" src="https://github.com/user-attachments/assets/030dd431-9af8-4a2b-acb4-63967cfe2bad" />
 

4. **Save Organization API Key**  
   - Now access you organization's user accound, go to **Account Settings > API Key** to generate/save your organization user’s API key.  
   - This will be used for **Shuffle integration**.  

5. You can press the **Cortex icon** in TheHive UI to view configured servers.
<img width="1230" height="653" alt="servers-for-new-org-TH" src="https://github.com/user-attachments/assets/38865937-3a0f-4cce-957c-844de6750646" />


---

# Shuffle Workflow

The implemented **Shuffle workflow logic** is illustrated in the flowchart at the beginning of this README.

## Wazuh Webhook Integration

- The workflow starts with a **webhook**, whose URL is copied into an **integration block** in Wazuh's `ossec.conf`.
- **Self-signed certificate issue**: Wazuh manager initially refuses the webhook due to authorization failure.  
  - Adding `verify=False` in `shuffle.py` was insufficient.  
  - Solution:
    1. Export Shuffle server certificate to a PEM file on the host:

    ```bash
    openssl s_client -connect "$SHUFFLE_ADDR" -showcerts </dev/null 2>/dev/null \
      | openssl x509 -outform PEM > shuffle-ca.crt
    ```

    2. Quick sanity check:

    ```bash
    head -n 2 shuffle-ca.crt   # should show: -----BEGIN CERTIFICATE-----
    ```

    3. Copy PEM into Wazuh manager container’s trust anchors:

    ```bash
    docker cp shuffle-ca.crt "$MANAGER":/etc/pki/ca-trust/source/anchors/shuffle-ca.crt
    ```

    4. Ensure CA tools are installed:

    ```bash
    docker exec "$MANAGER" sh -c 'command -v yum >/dev/null && yum -y install ca-certificates || true'
    ```

    5. Rebuild the system CA bundle:

    ```bash
    docker exec "$MANAGER" update-ca-trust extract
    ```

    6. Verify the Shuffle cert is trusted:

    ```bash
    docker exec "$MANAGER" \
      openssl s_client -connect "$SHUFFLE_ADDR" -CAfile /etc/ssl/certs/ca-bundle.crt </dev/null \
      | sed -n '/Verify return code/,$p'   # should show "Verify return code: 0 (ok)..."
    ```

- After this, **Wazuh alerts flow successfully** to Shuffle.

---

## Workflow Nodes

1. **Webhook Node** → connected to **Parse IOCs Node**
   - Correctly parses IPs and hashes.
     <img width="1501" height="863" alt="ip-wf-1" src="https://github.com/user-attachments/assets/b26ffbe1-340a-4a80-beb3-73a726795a59" />

2. **TheHive Alert Creation Node** → branches conditionally:
   - **Add Observables Nodes** branch conditions:
     - For hashes → logs must include `syscheck`
     - For IPs → logs must include `journald`
   - Alerts are created and observables are linked accordingly.
    here's a FIM alert with the parsed IOCs linked as observables:
    <img width="1405" height="338" alt="ip-wf-2-1" src="https://github.com/user-attachments/assets/5311bb9a-d7a5-48ac-93c9-a16cf60ca5dd" />
   <img width="1490" height="621" alt="hash-alert" src="https://github.com/user-attachments/assets/1389deb9-8273-43f6-8873-317988e89926" />
 <img width="1173" height="608" alt="hash-observables" src="https://github.com/user-attachments/assets/c0ad37a5-8fa8-414f-8c68-96a1f5fb9613" />

3. **Cortex Nodes** (consecutive):
   1. **Get Available Analyzers** → references datatype and data from Parse IOCs node.
   3. **Run Analyzers** → uses previous node output as analyzer names (list access via `.#`).
    <img width="1511" height="894" alt="ip-wf-3" src="https://github.com/user-attachments/assets/784c65c6-07ea-4cb5-9764-fbbcb1459bb9" />
    
   5. **Get Analyzer Results** → references previous node output (`.#`) again.
    <img width="1495" height="875" alt="ip-wf-4" src="https://github.com/user-attachments/assets/07b7bb12-fbbd-4143-a633-05b08e16e117" />

4. **Filter Node**:
   - Checks if both analyzer results flag the IOC as malicious.
   - Non-malicious → workflow terminates.
   - Malicious → workflow continues.
5. **Update Alert Node**
   -Uses the analyzers report results to update the created alert
   <img width="1496" height="845" alt="ip-wf-5" src="https://github.com/user-attachments/assets/9388aa75-be72-4511-8cac-16312cd279fa" />
   the update alerts with the analyzers' tags:
   <img width="1920" height="843" alt="ip-wf-5-1" src="https://github.com/user-attachments/assets/37e7ed65-64ef-4644-b409-e6d05632930e" />

---

## Severity-based Branching

- **If IOC is malicious**, branch based on alert severity:
  1. **Severity < 6 (Wazuh Active-Response)**:
     - Get Wazuh API token.
       <img width="1502" height="891" alt="wazuh-api-token" src="https://github.com/user-attachments/assets/a7d5a453-933e-401e-ba4b-183bbfd68c67" />
     - Activate active-response using PUT command.
      <img width="1507" height="882" alt="wazuh-ar" src="https://github.com/user-attachments/assets/ead4265c-93bf-4456-9c4b-78156936d65a" />

  2. **Severity ≥ 6**:
     - Create TheHive case from alert.
       <img width="1492" height="878" alt="high-severity-case-creation" src="https://github.com/user-attachments/assets/31e43471-a047-43c1-8032-5e5e0a85aafb" />
      the created cases in TheHive show with the linked alert:
      <img width="1920" height="849" alt="linked-alerts" src="https://github.com/user-attachments/assets/6e52b675-2a01-49a5-a69c-74bb523d4a45" />
      <img width="1920" height="827" alt="linked-alert-detail" src="https://github.com/user-attachments/assets/0ec09b85-0493-44da-9494-b94ae03f2852" />
     -Get case Artifacts
    <img width="1507" height="893" alt="getartifacts" src="https://github.com/user-attachments/assets/b6078a1c-9a62-478f-aceb-4aa283eeb673" />

     - Run in-app analyzers for detailed analyst review. The full aler can be parsed in TheHIve case:
       <img width="1920" height="856" alt="in-app-analyzers" src="https://github.com/user-attachments/assets/6238d485-b613-4300-b95b-b27375707c3e" />

     
