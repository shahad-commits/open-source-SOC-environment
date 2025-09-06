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


Wazuh
Deployment

Followed the Wazuh Docker Guide

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
> **Note:** Default login: admin@admin.test:admin.
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




