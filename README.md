# CMU-CS 376: Apache Web Server Security Hardening & AI/ML Log Analysis

**Student:** Huynh Thi Kim Hue 
**Student ID:** 30209256285 
**Course:** CMU-CS 376 - Elements of Network Security  
**Instructor:** MSc. Le Van Tinh 

---

##  Project Overview
This project focuses on hardening an Apache Web Server, deploying HTTPS/TLS encryption using OpenSSL, integrating ModSecurity WAF with OWASP CRS to block Layer 7 web attacks (SQLi, XSS), and utilizing a Python-based Isolation Forest Machine Learning model for automated access log analysis.

##  Repository Structure
- `src/analyze_log.py`: Python script using Pandas and Scikit-Learn for parsing `access.log` and detecting anomalous access behavior.
- `config/security.conf`: Apache security configuration to hide server banners (`ServerTokens Prod`, `ServerSignature Off`).
- `config/modsecurity.conf`: WAF configuration set to active blocking mode (`SecRuleEngine On`).
- `config/apache-selfsigned.conf`: VirtualHost SSL/TLS configuration for HTTPS on port 443.

## How to Run
1. **Apply Configurations:** Copy files in `config/` to `/etc/apache2/` and restart Apache.
2. **Run Log Analysis Script:**
   ```bash
   sudo python3 src/analyze_log.py