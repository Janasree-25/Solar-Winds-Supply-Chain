# 🛡️ SolarWinds Supply Chain Defense Case Study Dashboard

A full-stack cybersecurity case study web application built with **Next.js (App Router)**, **TypeScript**, **Tailwind CSS**, and **MariaDB**.

Includes an interactive **SQL Query Console** to execute live queries against the database and visualize the SolarWinds SUNBURST attack vectors, affected organizations, CVE vulnerabilities, timeline, and defense measures.

---

## 🌟 Key Features

- **📊 Case Study Dashboard**:
  - **Overview**: Threat actors (APT29 / Cozy Bear), software versions (trojanized vs clean).
  - **Attack Incidents**: Detailed phases, severities, and targets across the attack lifecycle.
  - **Interactive Timeline**: 24 chronological events from initial build system intrusion to national policy responses.
  - **Affected Organizations**: Breakdown of compromised vs suspected government and enterprise entities.
  - **Vulnerabilities Tracker**: CVSS scoring visualization for CVE-2020-10148, CVE-2021-35211, and related flaws.
  - **Defense Measures**: Zero Trust, IOC detection rules, Golden SAML mitigations, and NIST SP 800-161 guidelines.
- **🖥️ Live SQL Query Runner**:
  - Built-in SQL editor with keyboard shortcuts (`Ctrl + Enter`).
  - 10 one-click preset queries for quick demonstration.
  - Real-time tabular output displaying execution time (ms), column count, and formatted rows.
  - Safe read-only execution (`SELECT`, `SHOW`, `DESCRIBE`, `EXPLAIN`).

---

## 🗄️ Database Architecture (MariaDB)

The project includes a ready-to-run schema and seed data in [`database/schema.sql`](./database/schema.sql):

- `threat_actors`: Threat group profiles, aliases, sophistication levels.
- `organizations`: Sector, country, breach status, compromised infrastructure.
- `software_versions`: Orion platform releases with trojan/clean status.
- `attack_incidents`: Attack vector mappings and impacts.
- `vulnerabilities`: CVE records with CVSS metrics and patch timelines.
- `defense_measures`: Countermeasures categorized by mitigation domain.
- `timeline_events`: Granular event log with severity classifications.

---

## 🚀 Getting Started

### 1. Prerequisites
- [Node.js](https://nodejs.org/) (v18+ recommended)
- [MariaDB](https://mariadb.org/) (running locally on port 3306)

### 2. Database Setup
Import the database schema and seed data into your local MariaDB instance:

```bash
# Using MariaDB CLI or MySQL Client
mysql -u root -p < database/schema.sql
```

### 3. Environment Variables
Copy `.env.example` to `.env.local`:

```bash
cp .env.example .env.local
```

Configure your credentials in `.env.local`:
```env
DB_HOST=localhost
DB_PORT=3306
DB_USER=root
DB_PASSWORD=your_password_here
DB_NAME=solarwinds_defense
```

### 4. Install Dependencies & Run

```bash
# Install dependencies
npm install

# Start development server
npm run dev
```

Open [http://localhost:3000](http://localhost:3000) in your browser.

---

## 🛠️ Tech Stack

- **Framework**: Next.js 16 (App Router)
- **Language**: TypeScript
- **Styling**: Tailwind CSS
- **Database**: MariaDB
- **DB Client**: `mysql2/promise` connection pooling
