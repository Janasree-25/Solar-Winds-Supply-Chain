-- SolarWinds Supply Chain Defense Database Schema
-- SUNBURST Attack Case Study

CREATE DATABASE IF NOT EXISTS solarwinds_defense;
USE solarwinds_defense;

-- ============================================================
-- TABLE: threat_actors
-- ============================================================
DROP TABLE IF EXISTS attack_incidents;
DROP TABLE IF EXISTS defense_measures;
DROP TABLE IF EXISTS vulnerabilities;
DROP TABLE IF EXISTS software_versions;
DROP TABLE IF EXISTS timeline_events;
DROP TABLE IF EXISTS organizations;
DROP TABLE IF EXISTS threat_actors;

CREATE TABLE threat_actors (
  id INT AUTO_INCREMENT PRIMARY KEY,
  name VARCHAR(255) NOT NULL,
  alias VARCHAR(255),
  origin_country VARCHAR(100),
  sophistication_level VARCHAR(50),
  first_observed DATE,
  description TEXT
);

-- ============================================================
-- TABLE: organizations
-- ============================================================
CREATE TABLE organizations (
  id INT AUTO_INCREMENT PRIMARY KEY,
  name VARCHAR(255) NOT NULL,
  sector VARCHAR(100),
  country VARCHAR(100),
  affected_date DATE,
  breach_status VARCHAR(50),
  systems_compromised TEXT,
  data_exfiltrated TEXT,
  description TEXT
);

-- ============================================================
-- TABLE: software_versions
-- ============================================================
CREATE TABLE software_versions (
  id INT AUTO_INCREMENT PRIMARY KEY,
  product_name VARCHAR(255) NOT NULL,
  version VARCHAR(100),
  release_date DATE,
  is_compromised BOOLEAN DEFAULT FALSE,
  malware_embedded VARCHAR(255),
  vulnerability_type VARCHAR(255),
  cve_id VARCHAR(50)
);

-- ============================================================
-- TABLE: attack_incidents
-- ============================================================
CREATE TABLE attack_incidents (
  id INT AUTO_INCREMENT PRIMARY KEY,
  incident_name VARCHAR(255) NOT NULL,
  attack_phase VARCHAR(100),
  date_occurred DATE,
  threat_actor_id INT,
  target_org_id INT,
  attack_vector TEXT,
  severity_level VARCHAR(20),
  description TEXT,
  impact TEXT,
  FOREIGN KEY (threat_actor_id) REFERENCES threat_actors(id),
  FOREIGN KEY (target_org_id) REFERENCES organizations(id)
);

-- ============================================================
-- TABLE: vulnerabilities
-- ============================================================
CREATE TABLE vulnerabilities (
  id INT AUTO_INCREMENT PRIMARY KEY,
  cve_id VARCHAR(50) NOT NULL,
  name VARCHAR(255),
  cvss_score DECIMAL(3,1),
  vulnerability_type VARCHAR(100),
  affected_software TEXT,
  date_published DATE,
  date_patched DATE,
  exploit_available BOOLEAN DEFAULT FALSE,
  description TEXT
);

-- ============================================================
-- TABLE: defense_measures
-- ============================================================
CREATE TABLE defense_measures (
  id INT AUTO_INCREMENT PRIMARY KEY,
  measure_name VARCHAR(255) NOT NULL,
  category VARCHAR(100),
  implementation_date DATE,
  effectiveness_rating INT,
  description TEXT,
  implementing_org VARCHAR(255)
);

-- ============================================================
-- TABLE: timeline_events
-- ============================================================
CREATE TABLE timeline_events (
  id INT AUTO_INCREMENT PRIMARY KEY,
  event_date DATE NOT NULL,
  event_title VARCHAR(255) NOT NULL,
  event_type VARCHAR(50),
  description TEXT,
  significance_level VARCHAR(20)
);

-- ============================================================
-- SEED DATA
-- ============================================================

-- Threat Actors
INSERT INTO threat_actors (name, alias, origin_country, sophistication_level, first_observed, description) VALUES
('APT29', 'Cozy Bear / The Dukes / Nobelium', 'Russia', 'Nation-State', '2008-01-01', 'Russian SVR (Foreign Intelligence Service) affiliated advanced persistent threat group. Responsible for the SolarWinds SUNBURST supply chain attack. Known for highly sophisticated, stealthy, long-term espionage campaigns targeting government, defense, energy, and technology sectors globally.'),
('SVR RF', 'Russian Foreign Intelligence Service', 'Russia', 'Nation-State', '1991-01-01', 'Russian foreign intelligence service (Sluzhba Vneshnei Razvedki). The government agency attributed as the primary sponsor of the SolarWinds supply chain compromise. Controls APT29 operations.'),
('Unknown Insider / Build System Compromiser', NULL, 'Unknown', 'Advanced', '2019-09-01', 'The initial attacker who compromised SolarWinds build pipeline in September 2019. Injected the SUNBURST trojanized code into the Orion software build process, enabling widespread supply chain infection.'),
('SPIRAL', 'Secondary Actor', 'Unknown', 'Advanced', '2020-10-01', 'A second threat actor identified by Symantec as having leveraged the SolarWinds compromise independently. Installed the Raindrop malware loader on compromised networks.'),
('UNC2452', 'Dark Halo / StellarParticle', 'Russia', 'Nation-State', '2020-06-01', 'FireEye/Mandiant tracking designation for the threat cluster responsible for SolarWinds. Associated with APT29/Cozy Bear. Known for patient dwell time and living-off-the-land techniques to avoid detection.');

-- Organizations
INSERT INTO organizations (name, sector, country, affected_date, breach_status, systems_compromised, data_exfiltrated, description) VALUES
('SolarWinds Corporation', 'Technology / Software', 'United States', '2019-09-01', 'Confirmed', 'Orion Platform build environment, software signing infrastructure, CI/CD pipeline', 'Source code, build system credentials, internal tools', 'Software company whose Orion IT monitoring platform was trojanized. The SUNBURST malware was embedded in Orion updates distributed to ~18,000 customers between March and June 2020.'),
('FireEye (Mandiant)', 'Cybersecurity', 'United States', '2020-11-01', 'Confirmed', 'Internal red team tools repository, penetration testing tool cache', 'Approximately 300 proprietary offensive security tools', 'Leading cybersecurity firm that first discovered the intrusion in December 2020 while investigating a theft of its own red team tools. FireEye''s discovery triggered the global disclosure of the SolarWinds campaign.'),
('US Department of Treasury', 'Government / Finance', 'United States', '2020-07-01', 'Confirmed', 'Microsoft Office 365 email systems, internal network', 'Sensitive financial communications, internal policy discussions', 'US Treasury department confirmed breach of email systems. Attackers monitored email traffic for months. Treasury''s Office of the Comptroller of the Currency was specifically targeted.'),
('US Department of Commerce', 'Government', 'United States', '2020-07-01', 'Confirmed', 'NTIA email systems (Microsoft Office 365)', 'Internal government communications', 'National Telecommunications and Information Administration (NTIA) email system was compromised. Attackers had access for months before discovery.'),
('Microsoft Corporation', 'Technology', 'United States', '2020-12-01', 'Confirmed', 'Internal source code repositories, Azure AD systems', 'Azure, Intune, Exchange source code (partial)', 'Microsoft confirmed attackers accessed its internal source code repositories. Also revealed the attackers used Microsoft services as infrastructure for the campaign. Microsoft 365 Defender telemetry was pivotal in tracking the campaign.'),
('US Department of Homeland Security', 'Government / Security', 'United States', '2020-07-01', 'Confirmed', 'Email systems, network management tools', 'Sensitive inter-agency communications', 'CISA (part of DHS) was compromised through the SolarWinds Orion platform despite being the nation''s primary cybersecurity agency. Led to significant reform of federal cybersecurity practices.'),
('Intel Corporation', 'Technology / Semiconductor', 'United States', '2020-08-01', 'Suspected', 'Internal network monitoring systems', 'Possible proprietary chip design data', 'Intel confirmed it had the SolarWinds Orion software but stated it found no evidence of breach. Listed as a suspected target due to Orion deployment.'),
('Cisco Systems', 'Technology / Networking', 'United States', '2020-09-01', 'Suspected', 'Network monitoring infrastructure', 'Unknown', 'Cisco confirmed it had SolarWinds Orion deployed in a lab environment but stated no production systems were impacted. Under ongoing investigation.'),
('NATO', 'International Organization / Defense', 'Belgium', '2020-08-01', 'Suspected', 'Network management tools', 'Unknown - potentially classified communications', 'NATO acknowledged having the SolarWinds software in its environment. Conducted internal investigation. Potential implications for classified alliance communications.'),
('UK Government NCSC', 'Government / Cybersecurity', 'United Kingdom', '2020-09-01', 'Suspected', 'Network monitoring infrastructure', 'Unknown', 'UK National Cyber Security Centre investigated potential exposure from SolarWinds Orion deployment in government networks. Issued guidance to UK public sector organizations.');

-- Software Versions
INSERT INTO software_versions (product_name, version, release_date, is_compromised, malware_embedded, vulnerability_type, cve_id) VALUES
('SolarWinds Orion Platform', '2019.4', '2020-03-26', TRUE, 'SUNBURST (Backdoor.Solorigate)', 'Supply Chain / Trojanized Build', NULL),
('SolarWinds Orion Platform', '2019.4 HF1', '2020-04-14', TRUE, 'SUNBURST (Backdoor.Solorigate)', 'Supply Chain / Trojanized Build', NULL),
('SolarWinds Orion Platform', '2019.4 HF2', '2020-05-11', TRUE, 'SUNBURST (Backdoor.Solorigate)', 'Supply Chain / Trojanized Build', NULL),
('SolarWinds Orion Platform', '2020.2', '2020-03-26', TRUE, 'SUNBURST (Backdoor.Solorigate)', 'Supply Chain / Trojanized Build', 'CVE-2020-10148'),
('SolarWinds Orion Platform', '2020.2 HF1', '2020-06-23', TRUE, 'SUNBURST (Backdoor.Solorigate) + SUPERNOVA', 'Supply Chain / API Auth Bypass', 'CVE-2020-10148'),
('SolarWinds Orion Platform', '2020.2.1', '2020-10-22', TRUE, 'SUNBURST (Backdoor.Solorigate)', 'Supply Chain / Trojanized Build', 'CVE-2020-10148'),
('SolarWinds Orion Platform', '2020.2.1 HF1', '2020-12-14', FALSE, NULL, 'Hotfix - Partially mitigated', NULL),
('SolarWinds Orion Platform', '2020.2.1 HF2', '2020-12-15', FALSE, NULL, 'Clean - SUNBURST removed', NULL),
('SolarWinds Serv-U FTP', '15.2.3 HF1', '2021-07-09', TRUE, 'SUPERNOVA Loader', 'Memory Escape / RCE', 'CVE-2021-35211'),
('SolarWinds N-central', '2020.1', '2020-06-01', FALSE, NULL, 'Not Affected', NULL);

-- Attack Incidents
INSERT INTO attack_incidents (incident_name, attack_phase, date_occurred, threat_actor_id, target_org_id, attack_vector, severity_level, description, impact) VALUES
('SolarWinds Build System Compromise', 'Initial Access', '2019-09-01', 1, 1, 'Supply chain attack via SolarWinds development environment compromise. TEARDROP dropper used to inject SUNBURST into build pipeline.', 'CRITICAL', 'APT29 breached SolarWinds internal development environment and injected the SUNBURST trojan into the Orion software build process. The malware laid dormant for ~2 weeks after installation before activation.', 'Enabled trojanized Orion updates to be signed and distributed to approximately 18,000 organizations worldwide.'),
('SUNBURST Malware Distribution', 'Execution', '2020-03-26', 1, 1, 'Legitimate software update mechanism used to distribute trojanized Orion packages signed with valid SolarWinds certificate.', 'CRITICAL', 'Trojanized Orion updates containing SUNBURST backdoor were distributed through SolarWinds'' official update mechanism. Updates were digitally signed with valid certificates, bypassing security controls.', '18,000+ organizations installed compromised updates. Approximately 100 organizations were subsequently targeted for further exploitation.'),
('FireEye Red Team Tool Theft', 'Collection / Exfiltration', '2020-11-01', 1, 2, 'SUNBURST backdoor used for lateral movement. Attackers pivoted to FireEye systems via compromised Orion installation.', 'CRITICAL', 'APT29 used the SUNBURST backdoor to access FireEye internal networks and steal approximately 300 proprietary red team tools. The theft was discovered by FireEye security team in December 2020.', 'Theft of powerful offensive security tools that could be weaponized. FireEye''s discovery triggered global disclosure.'),
('US Treasury Email System Breach', 'Collection / Exfiltration', '2020-07-01', 1, 3, 'SUNBURST backdoor → TEARDROP malware → Golden SAML attack against Microsoft 365', 'CRITICAL', 'Attackers used the SUNBURST backdoor to pivot to US Treasury''s Microsoft 365 environment using forged SAML tokens (Golden SAML attack). Monitored email communications of senior officials.', 'Months of senior Treasury official email access. Potential exposure of sensitive financial policy discussions.'),
('NTIA Commerce Department Breach', 'Collection / Exfiltration', '2020-07-01', 1, 4, 'SUNBURST backdoor used for lateral movement into NTIA email environment.', 'HIGH', 'National Telecommunications and Information Administration email system was breached. Attackers gained access to Microsoft Office 365 email accounts of NTIA staff.', 'Internal government communications exposed. Impact on telecommunications policy discussions unknown.'),
('Microsoft Source Code Access', 'Collection', '2020-12-01', 1, 5, 'Compromised SolarWinds Orion installation on Microsoft network used for lateral movement to internal code repositories.', 'HIGH', 'Attackers gained access to Microsoft internal source code repositories for Azure, Intune, and Exchange products. Microsoft confirmed the access did not result in code modification or customer data exposure.', 'Potential exposure of proprietary source code. Microsoft used its visibility to track and map the attacker infrastructure globally.'),
('DHS CISA Network Compromise', 'Collection', '2020-07-01', 1, 6, 'SolarWinds Orion backdoor deployed within CISA infrastructure.', 'CRITICAL', 'US Department of Homeland Security including CISA was compromised through its own SolarWinds Orion deployment, creating a significant irony as CISA is responsible for protecting federal cybersecurity.', 'Sensitive inter-agency cybersecurity communications exposed. Led to emergency directive ED 21-01 and significant federal security reforms.'),
('Serv-U FTP RCE Exploitation', 'Exploitation', '2021-07-01', 1, 1, 'Remote code execution via memory escape vulnerability in SolarWinds Serv-U FTP and MFT server.', 'CRITICAL', 'Separate from SUNBURST, APT29 exploited CVE-2021-35211 in SolarWinds Serv-U to achieve remote code execution with SYSTEM privileges. Used to install SUPERNOVA malware loader.', 'Remote code execution on Serv-U servers. Enabled persistent access independent of the Orion supply chain attack.');

-- Vulnerabilities
INSERT INTO vulnerabilities (cve_id, name, cvss_score, vulnerability_type, affected_software, date_published, date_patched, exploit_available, description) VALUES
('CVE-2020-10148', 'SolarWinds Orion API Authentication Bypass', 9.8, 'Authentication Bypass', 'SolarWinds Orion Platform 2019.4 through 2020.2.1', '2020-12-26', '2020-12-15', TRUE, 'A critical authentication bypass vulnerability in the SolarWinds Orion API that allows a remote attacker to bypass authentication and execute API commands. The SUNBURST backdoor exploited this to create and execute malicious commands. CVSS v3.1 score 9.8 (Critical).'),
('CVE-2021-35211', 'SolarWinds Serv-U RCE via Memory Escape', 10.0, 'Remote Code Execution', 'SolarWinds Serv-U FTP Server 15.2.3 HF1 and prior, Serv-U MFT Server 15.2.3 HF1 and prior', '2021-07-09', '2021-07-09', TRUE, 'A critical memory escape vulnerability in SolarWinds Serv-U FTP and managed file transfer server allowing remote code execution with SYSTEM privileges. Actively exploited by APT29 in the wild. CVSS v3.1 score 10.0 (Critical).'),
('CVE-2021-25275', 'SolarWinds SIEM Insecure Deserialization', 7.8, 'Insecure Deserialization', 'SolarWinds Security Event Manager (SIEM) before 2021.1', '2021-02-03', '2021-02-03', TRUE, 'An insecure deserialization vulnerability in SolarWinds SIEM that allows an authenticated attacker to execute arbitrary code. Part of broader SolarWinds security review following SUNBURST disclosure.'),
('CVE-2021-25274', 'SolarWinds MSMQ Deserialization RCE', 9.8, 'Remote Code Execution', 'SolarWinds Orion Platform before 2020.2.4, SolarWinds SIEM before 2021.1', '2021-02-03', '2021-02-03', TRUE, 'Critical RCE via MSMQ message deserialization in SolarWinds Orion. An unauthenticated attacker can send a crafted MSMQ message to execute arbitrary code as SYSTEM.'),
('CVE-2020-14005', 'SolarWinds Orion OGNL Injection', 9.0, 'Code Injection', 'SolarWinds Orion Platform 2018.4 through 2019.4.1', '2020-06-09', '2020-07-09', TRUE, 'An OGNL injection vulnerability in the SolarWinds Orion Platform that allows remote authenticated users to execute arbitrary code via the search function. Precedes SUNBURST but part of the same platform.'),
('CVE-2021-35222', 'SolarWinds Orion CSRF Token Disclosure', 6.1, 'Information Disclosure', 'SolarWinds Orion Platform 2020.2.6 and prior', '2021-09-30', '2021-09-30', FALSE, 'A cross-site scripting (XSS) vulnerability in the SolarWinds Orion Platform that allows remote attackers to steal CSRF tokens and perform actions on behalf of authenticated users.'),
('CVE-2021-31474', 'SolarWinds N-Central Arbitrary File Read', 9.1, 'Path Traversal', 'SolarWinds N-Central before 2021.1 SP1 HF5', '2021-04-22', '2021-04-22', TRUE, 'A path traversal vulnerability in SolarWinds N-Central server allowing unauthenticated attackers to read arbitrary files from the server filesystem, potentially exposing credentials and sensitive configuration.'),
('CVE-2019-8917', 'SolarWinds Orion Remote Code Execution', 9.8, 'Remote Code Execution', 'SolarWinds Orion Network Performance Monitor 12.3 and prior', '2019-03-13', '2019-04-01', TRUE, 'A pre-authentication RCE vulnerability in SolarWinds Orion NPM. Part of the broader historical vulnerability pattern that made SolarWinds a high-value target for sophisticated threat actors.');

-- Defense Measures
INSERT INTO defense_measures (measure_name, category, implementation_date, effectiveness_rating, description, implementing_org) VALUES
('SUNBURST IOC Detection Rules', 'Detection', '2020-12-14', 5, 'FireEye and Microsoft released comprehensive YARA and SNORT rules for detecting SUNBURST malware on endpoints, in network traffic, and in memory. Included 300+ indicators of compromise (IOCs) for the malicious DLL (SolarWinds.Orion.Core.BusinessLayer.dll) and C2 domains (avsvmcloud.com).', 'FireEye / Microsoft / CISA'),
('Emergency Directive ED 21-01', 'Policy / Compliance', '2020-12-18', 4, 'CISA issued Emergency Directive 21-01 requiring all federal agencies to immediately disconnect or power down SolarWinds Orion products. Agencies required to report all instances of SolarWinds software within 24 hours.', 'CISA / US Government'),
('Golden SAML Detection', 'Detection / Forensics', '2021-01-01', 5, 'Development of detection methodologies for forged SAML tokens (Golden SAML attack). Involves monitoring Azure AD sign-in logs for impossible travel, unusual service principal activity, and token lifetime anomalies.', 'CrowdStrike / Microsoft'),
('Zero Trust Architecture Implementation', 'Prevention', '2021-03-01', 5, 'Federal mandate to implement Zero Trust Architecture across government agencies. Eliminates implicit trust based on network location. Requires continuous verification of identity and device health for all resource access.', 'US Federal Government / OMB'),
('Software Build Pipeline Security Review', 'Prevention', '2021-02-01', 4, 'Comprehensive security audit of software build and release pipelines across critical software vendors. Includes code signing policy enforcement, build environment isolation, integrity verification of build artifacts, and supply chain risk management.', 'SolarWinds / NIST / Industry'),
('SolarWinds Orion Hotfix 2020.2.1 HF2', 'Remediation', '2020-12-15', 5, 'Emergency hotfix released by SolarWinds removing the SUNBURST backdoor from affected Orion versions. Customers required to upgrade immediately and conduct forensic investigation of their environments.', 'SolarWinds'),
('SUNBURST C2 Domain Sinkholing', 'Containment', '2020-12-16', 5, 'Microsoft, FireEye, and GoDaddy coordinated to sinkhole the avsvmcloud.com domain used by SUNBURST for C2 communication. This disabled the backdoor for all infected hosts simultaneously.', 'Microsoft / FireEye / GoDaddy'),
('CISA Hunt and Incident Response Service', 'Detection / Response', '2021-01-01', 4, 'CISA deployed dedicated Hunt and Incident Response teams to assist affected federal agencies in identifying compromised systems, conducting forensic analysis, and remediating the SUNBURST compromise.', 'CISA'),
('Multi-Factor Authentication Enforcement', 'Prevention', '2021-06-01', 5, 'Mandatory MFA for all federal agency systems following Executive Order 14028. Prevents Golden SAML attacks and credential-based lateral movement used in the SolarWinds campaign.', 'US Federal Government'),
('Supply Chain Risk Management Framework (C-SCRM)', 'Prevention', '2021-10-01', 4, 'NIST updated SP 800-161 with comprehensive guidance for managing cybersecurity supply chain risks. Requires software bill of materials (SBOM), vendor security assessments, and continuous monitoring of third-party software.', 'NIST / Industry');

-- Timeline Events
INSERT INTO timeline_events (event_date, event_title, event_type, description, significance_level) VALUES
('2019-09-01', 'Initial SolarWinds Build System Compromise', 'attack', 'APT29 successfully compromises SolarWinds development environment. Attackers gain access to the Orion software build pipeline and begin preparations to inject the SUNBURST backdoor.', 'CRITICAL'),
('2019-10-01', 'SUNBURST Test Injection', 'attack', 'Attackers inject a test version of the SUNBURST malicious code into the Orion build process. This test version is quickly removed, confirming the technique works before the actual attack.', 'HIGH'),
('2020-02-20', 'SUNBURST Malicious Code Injected into Build', 'attack', 'The production version of SUNBURST backdoor code is injected into the SolarWinds Orion Platform source code. The code is compiled and included in legitimate software builds.', 'CRITICAL'),
('2020-03-26', 'Trojanized Orion Update Released', 'attack', 'SolarWinds releases Orion Platform version 2019.4 HF5 through its official update mechanism. This update contains the SUNBURST backdoor, signed with valid SolarWinds code-signing certificate.', 'CRITICAL'),
('2020-04-01', 'SUNBURST Dormancy Period Begins', 'attack', 'SUNBURST enters a 12-14 day dormancy period after installation. The malware performs reconnaissance to determine if it is in a sandbox or analysis environment before activating.', 'HIGH'),
('2020-05-01', 'SUNBURST Begins C2 Communication', 'attack', 'After dormancy, SUNBURST begins beaconing to attacker-controlled infrastructure via DNS queries to avsvmcloud.com. C2 traffic masquerades as legitimate Orion telemetry data.', 'CRITICAL'),
('2020-06-01', 'Targeted Exploitation of High-Value Organizations', 'attack', 'Attackers begin selectively deploying TEARDROP/RAINDROP second-stage malware against high-value targets including US government agencies and cybersecurity firms.', 'CRITICAL'),
('2020-06-23', 'Orion 2020.2 HF1 Distributed (Also Compromised)', 'attack', 'SolarWinds releases another compromised update (2020.2 HF1) continuing the supply chain attack vector.', 'HIGH'),
('2020-07-01', 'US Treasury and Commerce Department Breach Confirmed', 'attack', 'APT29 establishes persistent access in US Treasury and NTIA (Commerce Dept) email systems using Golden SAML attack against Microsoft 365.', 'CRITICAL'),
('2020-10-01', 'SUNBURST C2 Communication Reduced', 'attack', 'Attackers begin scaling back SUNBURST C2 activity, possibly aware of detection risk. Focus shifts to maintaining access via TEARDROP and legitimate credentials.', 'MEDIUM'),
('2020-11-01', 'FireEye Detects Anomalous Activity', 'discovery', 'FireEye security analysts detect unusual activity in their network related to an employee registering an MFA device from an unexpected location. Investigation begins.', 'CRITICAL'),
('2020-12-08', 'FireEye Publicly Discloses Breach and Red Team Tool Theft', 'discovery', 'FireEye publishes blog post disclosing that a sophisticated nation-state attacker stole its red team tools. This is the first public indicator of the broader SolarWinds campaign.', 'CRITICAL'),
('2020-12-13', 'SolarWinds SUNBURST Publicly Disclosed', 'discovery', 'FireEye, Microsoft, and GoDaddy jointly disclose the SolarWinds supply chain attack. SolarWinds confirms the Orion trojanization. CISA issues Emergency Directive 21-01.', 'CRITICAL'),
('2020-12-14', 'Microsoft Seizes avsvmcloud.com C2 Domain', 'response', 'Microsoft takes control of the primary SUNBURST C2 domain (avsvmcloud.com) by court order, effectively sinkholing all SUNBURST backdoor communications globally. A kill switch for the backdoor.', 'CRITICAL'),
('2020-12-15', 'SolarWinds Releases Clean Hotfix 2020.2.1 HF2', 'response', 'SolarWinds releases emergency hotfix removing the SUNBURST backdoor. Organizations worldwide begin emergency patching and forensic investigation of their environments.', 'HIGH'),
('2020-12-17', 'US Government Confirms Widespread Impact', 'discovery', 'US government confirms multiple agencies were breached including Treasury, Commerce, Homeland Security, parts of the Pentagon, and others. President-elect Biden briefed on the attack.', 'CRITICAL'),
('2020-12-24', 'Microsoft Confirms Its Own Breach', 'discovery', 'Microsoft confirms that attackers accessed its internal source code repositories but states no production systems or customer data were compromised.', 'HIGH'),
('2021-01-05', 'US Intelligence Community Attribution to Russia', 'attribution', 'The FBI, CISA, ODNI, and NSA jointly attribute the SolarWinds attack to Russia, likely the SVR (Foreign Intelligence Service). This is a rare formal attribution by the US intelligence community.', 'CRITICAL'),
('2021-01-19', 'SolarWinds Discloses Full Scope of Compromise', 'discovery', 'SolarWinds reveals that approximately 18,000 customers downloaded the compromised update, with approximately 100 organizations receiving targeted follow-on attacks.', 'HIGH'),
('2021-04-15', 'Biden Administration Sanctions Russia', 'response', 'US imposes sanctions on Russia including expulsion of 10 Russian diplomats and economic sanctions in response to the SolarWinds cyberattack and election interference.', 'HIGH'),
('2021-05-12', 'Executive Order 14028 on Cybersecurity', 'response', 'President Biden signs Executive Order 14028 mandating sweeping improvements to federal cybersecurity including Zero Trust adoption, MFA requirements, EDR deployment, and software supply chain security.', 'CRITICAL'),
('2021-07-09', 'Serv-U CVE-2021-35211 Disclosed and Patched', 'discovery', 'A separate critical RCE vulnerability (CVE-2021-35211) in SolarWinds Serv-U FTP is disclosed. Actively exploited by APT29. Emergency patch released same day.', 'HIGH'),
('2021-10-01', 'NIST Updates Supply Chain Risk Management Guidelines', 'response', 'NIST releases updated Special Publication 800-161 with comprehensive supply chain risk management guidance incorporating lessons from the SolarWinds attack.', 'MEDIUM'),
('2022-06-01', 'SolarWinds Orion Market Recovery and Security Overhaul', 'response', 'SolarWinds completes comprehensive security overhaul of its development and build processes under the "Secure by Design" initiative. Implements build integrity verification, isolated build environments, and continuous security testing.', 'MEDIUM');
