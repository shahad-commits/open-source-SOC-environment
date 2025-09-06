# SOC Orchestration — Shuffle Workflow Integration
![Project logos](assets/logos/shuffle-logo.png)

> Automated pipeline that ingests Wazuh alerts → extracts IOCs → enriches via MISP, TheHive/Cortex → performs Cortex analysis → triggers Wazuh active-response or TheHive case creation depending on severity — fully reproducible with Docker and Shuffle.

---

## Contents
- [Architecture & Flowchart](#architecture--flowchart)
- [Quickstart (dev)](#quickstart-dev)
- [Component setup order](#component-setup-order)
- [Shuffle workflow overview](#shuffle-workflow-overview)
- [Security & secrets](#security--secrets)
- [Troubleshooting & logs](#troubleshooting--logs)
- [Contributing](#contributing)
- [License](#license)

---

## Architecture & Flowchart

**Project architecture (high-level)**  
![Architecture diagram](assets/diagrams/architecture-diagram.png)

**Shuffle workflow flowchart**  
![Shuffle flowchart](assets/diagrams/shuffle-workflow-flowchart.png)

> Both diagrams are exports from draw.io. See `/assets/diagrams/` for the source `.drawio` or `.xml` if you want to edit them.

---

