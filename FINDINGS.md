# Detailed Security Findings Report
## Government Healthcare Website Vulnerability Assessment

**Target:** https://health.gov.gy  
**Assessment Date:** January 25, 2020  
**Researcher:** Raja R  
**Report Version:** 1.0  
**Classification:** Responsible Disclosure

---

## 📋 Table of Contents

1. [Executive Summary](#executive-summary)
2. [Testing Scope & Methodology](#testing-scope--methodology)
3. [Vulnerability #1: Clickjacking](#vulnerability-1-clickjacking)
4. [Vulnerability #2: Directory Listing Exposure](#vulnerability-2-directory-listing-exposure)
5. [Vulnerability #3: Missing Security Headers](#vulnerability-3-missing-security-headers)
6. [Risk Assessment](#risk-assessment)
7. [Remediation Roadmap](#remediation-roadmap)
8. [Appendix](#appendix)

---

## Executive Summary

This report documents security vulnerabilities discovered in the Guyana Ministry of Health website (health.gov.gy) through ethical security research. The assessment identified multiple security misconfigurations that could potentially lead to information disclosure and compromise user security.

### Key Statistics:
- **Total Vulnerabilities Found:** 3 confirmed
- **Critical:** 0
- **High:** 1 (Directory Listing)
- **Medium:** 2 (Clickjacking, Missing Headers)
- **Low:** 0

### Overall Risk Rating: **MEDIUM-HIGH**

---

## Testing Scope & Methodology

### Testing Environment
- **Target Domain:** health.gov.gy
- **Testing Period:** January 25-27, 2020
- **Testing Type:** External Black-box Security Assessment
- **Authorization:** Unauthorized testing (Ethical/Educational research)
- **Tools Used:** Burp Suite Community, Browser DevTools, Custom Scripts

### Methodology Framework

**OWASP Testing Guide v4 Methodology:**

1. **Information Gathering (Reconnaissance)**
   - Passive reconnaissance using search engines
   - Google Dorking for exposed resources
   - DNS enumeration and subdomain discovery
   - Technology fingerprinting

2. **Configuration & Deployment Management Testing**
   - HTTP header analysis
   - Directory listing assessment
   - Error handling evaluation
   - Server configuration review

3. **Identity Management Testing**
   - Session management analysis
   - Cookie security assessment

4. **Authentication Testing**
   - Login mechanism review

5. **Client-Side Testing**
   - Clickjacking vulnerability assessment
   - Cross-Site Scripting (XSS) testing

### Testing Constraints

**In-Scope:**
✅ Public-facing web pages  
✅ HTTP/HTTPS configuration  
✅ Client-side vulnerabilities  
✅ Information disclosure  

**Out-of-Scope:**
❌ Authenticated areas (no credentials provided)  
❌ Denial of Service testing  
❌ Social engineering  
❌ Physical security  
❌ Internal network testing  

---

## Vulnerability #1: Clickjacking

### 🔴 Severity: MEDIUM
**CVSS v3.1 Score:** 4.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N)

### Vulnerability Details

**CWE Classification:** CWE-1021 - Improper Restriction of Rendered UI Layers or Frames  
**OWASP Category:** A05:2021 - Security Misconfiguration  
**Vulnerability Type:** Clickjacking / UI Redressing

### Technical Description

The target website lacks proper frame-busting protections, specifically the X-Frame-Options HTTP response header. This allows the website to be embedded within an iframe on attacker-controlled domains, enabling clickjacking attacks.

### Discovery Process

**Step 1: Initial Header Analysis**
```bash
# HTTP Request
GET / HTTP/1.1
Host: health.gov.gy
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)
Accept: text/html
```

**Step 2: Response Analysis**
```bash
# HTTP Response (relevant headers)
HTTP/1.1 200 OK
Content-Type: text/html; charset=UTF-8
Server: [Server Type]

# MISSING HEADERS:
# X-Frame-Options: [NOT PRESENT]
# Content-Security-Policy: [NOT PRESENT]
```

**Step 3: Proof of Concept Development**

Created a test HTML file to demonstrate iframe embedding:

```html
<!DOCTYPE html>
<html>
<head>
    <title>Clickjacking Vulnerability POC</title>
    <style>
        iframe {
            width: 100%;
            height: 600px;
            border: 2px solid red;
        }
        .overlay {
            position: absolute;
            top: 200px;
            left: 300px;
            opacity: 0.5;
            background: yellow;
            padding: 20px;
        }
    </style>
</head>
<body>
    <h1>Clickjacking Vulnerability Demonstration</h1>
    <p>The website below can be embedded in an iframe:</p>
    
    <!-- Target website successfully loads -->
    <iframe src="https://health.gov.gy/"></iframe>
    
    <div class="overlay">
        <p>Attacker could place transparent layer here</p>
    </div>
</body>
</html>
```

**Step 4: Validation**
- ✅ Website loaded successfully in iframe
- ✅ No frame-busting JavaScript detected
- ✅ No X-Frame-Options header present
- ✅ No CSP frame-ancestors directive

### Attack Scenario

**Exploitation Flow:**

1. **Attacker Setup:**
   - Creates malicious website with transparent iframe
   - Positions legitimate website behind fake UI elements
   - Uses CSS to overlay malicious buttons over legitimate ones

2. **Victim Interaction:**
   - User visits attacker's website
   - Believes they're clicking on attacker's content
   - Actually clicking on health.gov.gy hidden beneath

3. **Potential Impacts:**
   - Unauthorized form submissions
   - Unintended navigation or downloads
   - Session hijacking if combined with other vulnerabilities
   - Social engineering attacks leveraging government website trust

### Real-World Impact Examples:

**Scenario 1: Form Manipulation**
```
User thinks: "I'm clicking 'Enter Competition' on attacker site"
Reality: Clicking "Submit Vaccination Registration" on health.gov.gy
Result: Unintended form submission with attacker-controlled data
```

**Scenario 2: Social Engineering**
```
Attacker claim: "Click here to verify your COVID vaccination"
Reality: User clicking on legitimate government form
Result: Confusion and potential data manipulation
```

### Evidence

**Screenshot:** `screenshots/01_clickjacking_poc.png`
- Shows successful iframe embedding
- Demonstrates lack of frame protection
- Visible overlay possibility

### Remediation

**Priority Level:** HIGH

**Solution 1: Implement X-Frame-Options (Recommended)**
```apache
# Apache Configuration
Header always set X-Frame-Options "DENY"

# For same-origin framing only:
# Header always set X-Frame-Options "SAMEORIGIN"
```

```nginx
# Nginx Configuration
add_header X-Frame-Options "DENY" always;

# For same-origin framing only:
# add_header X-Frame-Options "SAMEORIGIN" always;
```

**Solution 2: Content Security Policy (Modern Approach)**
```
Content-Security-Policy: frame-ancestors 'none';

# For same-origin framing only:
# Content-Security-Policy: frame-ancestors 'self';
```

**Solution 3: JavaScript Frame-Busting (Backup - Not Recommended Alone)**
```javascript
// Top-level frame enforcement
if (top !== self) {
    top.location = self.location;
}
```

**Verification After Fix:**
```bash
# Expected response headers after remediation:
X-Frame-Options: DENY
Content-Security-Policy: frame-ancestors 'none'
```

---

## Vulnerability #2: Directory Listing Exposure

### 🔴 Severity: HIGH
**CVSS v3.1 Score:** 6.5 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N)

### Vulnerability Details

**CWE Classification:** CWE-548 - Exposure of Information Through Directory Listing  
**OWASP Category:** A01:2021 - Broken Access Control  
**Vulnerability Type:** Information Disclosure / Server Misconfiguration

### Technical Description

The web server is configured to display directory listings when accessing directories without index files. This exposes the complete file structure, file names, sizes, and modification dates to any user without authentication.

### Discovery Process

**Phase 1: OSINT Reconnaissance**

```bash
# Google Dorking Query
Search Query: inurl:"index of" gov.gy

# Results revealed:
- Multiple government websites with directory listing enabled
- health.gov.gy/data/ identified as vulnerable
- Exposed file structure visible in search results
```

**Phase 2: Manual Verification**

```bash
# Direct browser access
URL: https://health.gov.gy/data/
Result: Directory listing displayed

# Observations:
- Complete file listing visible
- File names, sizes, dates exposed
- No authentication required
- Multiple subdirectories accessible
```

**Phase 3: Burp Suite Analysis**

```http
# HTTP Request
GET /data/ HTTP/1.1
Host: health.gov.gy
User-Agent: Mozilla/5.0
Accept: text/html

# HTTP Response
HTTP/1.1 200 OK
Content-Type: text/html
Server: [Server Information]

<html>
<head><title>Index of /data/</title></head>
<body>
<h1>Index of /data/</h1>
<pre>
[Icon] Name                    Last modified      Size
-------------------------------------------------------
[DIR] subdirectory1/          DD-Mon-YYYY HH:MM    -
[FILE] document.pdf           DD-Mon-YYYY HH:MM  XXkB
[FILE] config_backup.txt      DD-Mon-YYYY HH:MM  XXkB
...
</pre>
</body>
</html>
```

### Exposed Information Categories

**File Types Potentially Exposed:**
- 📄 PDF documents and reports
- 📊 Excel/CSV data files
- 🖼️ Images and media files
- ⚙️ Configuration files (if present)
- 💾 Backup files
- 📁 Database exports
- 📝 Log files

**Information Disclosure Risks:**
1. **System Architecture:** File organization reveals application structure
2. **Sensitive Data:** Potential exposure of confidential documents
3. **Configuration Details:** Server paths and file naming conventions
4. **Backup Files:** Old versions may contain additional vulnerabilities
5. **Reconnaissance Aid:** Helps attackers plan further attacks

### Attack Scenarios

**Scenario 1: Data Exfiltration**
```
1. Attacker discovers directory listing
2. Enumerates all accessible files
3. Downloads sensitive documents or data
4. Uses information for further attacks or public disclosure
```

**Scenario 2: Configuration File Discovery**
```
1. Attacker searches for common config file names
2. Finds .env, config.php, or database.yml
3. Obtains database credentials or API keys
4. Gains unauthorized database access
```

**Scenario 3: Backup File Exploitation**
```
1. Identifies backup files (*.bak, *.old, *.backup)
2. Downloads archived source code
3. Analyzes code for vulnerabilities
4. Exploits vulnerabilities in production system
```

### Real-World Impact

**Confidentiality Breach:**
- Public health data potentially exposed
- Patient information at risk (if present in files)
- Internal documents accessible without authorization

**Compliance Violations:**
- GDPR violations (if EU citizen data exposed)
- Data Protection Act violations
- Healthcare data privacy regulations

**Reputation Damage:**
- Loss of public trust in government healthcare system
- Media attention and public scrutiny
- Potential legal consequences

### Evidence

**Screenshot:** `screenshots/02_burp_suite_analysis.png`
- Burp Suite traffic capture
- HTTP request/response showing directory listing
- Server response headers
- Directory content visible

### Remediation

**Priority Level:** CRITICAL

**Immediate Actions:**

**1. Disable Directory Listing (Apache)**
```apache
# In .htaccess or httpd.conf
Options -Indexes

# Per-directory configuration
<Directory "/var/www/html/data">
    Options -Indexes
</Directory>

# Global configuration
<Directory />
    Options -Indexes -FollowSymLinks
    AllowOverride None
</Directory>
```

**2. Disable Directory Listing (Nginx)**
```nginx
# In nginx.conf or site configuration
location / {
    autoindex off;
}

# Specific location
location /data/ {
    autoindex off;
    deny all;  # If directory should be completely inaccessible
}
```

**3. Disable Directory Listing (IIS)**
```xml
<!-- In web.config -->
<configuration>
  <system.webServer>
    <directoryBrowse enabled="false" />
  </system.webServer>
</configuration>
```

**Additional Security Measures:**

**1. Add Index Files**
```bash
# Create index.html in all directories
echo "Access Denied" > /var/www/html/data/index.html
```

**2. Implement Access Controls**
```apache
# Restrict directory access
<Directory "/var/www/html/data">
    Order Deny,Allow
    Deny from all
    Allow from 10.0.0.0/8  # Internal network only
</Directory>
```

**3. Move Sensitive Files**
```bash
# Store sensitive files outside web root
# Web root: /var/www/html/
# Sensitive files: /var/www/secure_data/

# Access via application logic only, not direct URLs
```

**Verification Steps:**

```bash
# Test after remediation:
curl -I https://health.gov.gy/data/

# Expected: 403 Forbidden or redirect to index page
# Not expected: 200 OK with directory listing
```

---

## Vulnerability #3: Missing Security Headers

### 🟡 Severity: LOW-MEDIUM
**CVSS v3.1 Score:** 3.7 (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N)

### Vulnerability Details

Multiple security-related HTTP headers are missing from server responses, reducing the overall security posture and leaving the application vulnerable to various client-side attacks.

### Missing Headers Analysis

**1. X-Content-Type-Options**
```
Status: MISSING
Risk: Medium
Impact: Enables MIME-sniffing attacks
```

**2. Strict-Transport-Security (HSTS)**
```
Status: MISSING
Risk: Medium
Impact: No HTTPS enforcement, protocol downgrade attacks possible
```

**3. Referrer-Policy**
```
Status: MISSING
Risk: Low
Impact: Information leakage via Referer header
```

**4. Permissions-Policy**
```
Status: MISSING  
Risk: Low
Impact: No control over browser features
```

### HTTP Response Analysis

**Current Response Headers:**
```http
HTTP/1.1 200 OK
Date: [Date]
Server: [Server]
Content-Type: text/html; charset=UTF-8
Content-Length: [Size]
Connection: keep-alive

# Missing critical security headers:
# X-Frame-Options: [MISSING] ✗
# Content-Security-Policy: [MISSING] ✗
# X-Content-Type-Options: [MISSING] ✗
# Strict-Transport-Security: [MISSING] ✗
# Referrer-Policy: [MISSING] ✗
# Permissions-Policy: [MISSING] ✗
```

**Recommended Response Headers:**
```http
HTTP/1.1 200 OK
X-Frame-Options: DENY
Content-Security-Policy: default-src 'self'; frame-ancestors 'none'
X-Content-Type-Options: nosniff
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
Referrer-Policy: strict-origin-when-cross-origin
Permissions-Policy: geolocation=(), microphone=(), camera=()
```

### Remediation

**Complete Security Headers Implementation:**

```apache
# Apache (.htaccess or httpd.conf)
<IfModule mod_headers.c>
    # Frame protection
    Header always set X-Frame-Options "DENY"
    
    # Content Security Policy
    Header always set Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; frame-ancestors 'none'"
    
    # MIME-sniffing protection
    Header always set X-Content-Type-Options "nosniff"
    
    # HTTPS enforcement (only if using HTTPS)
    Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"
    
    # Referrer policy
    Header always set Referrer-Policy "strict-origin-when-cross-origin"
    
    # Feature policy
    Header always set Permissions-Policy "geolocation=(), microphone=(), camera=()"
</IfModule>
```

```nginx
# Nginx (nginx.conf)
add_header X-Frame-Options "DENY" always;
add_header Content-Security-Policy "default-src 'self'; frame-ancestors 'none'" always;
add_header X-Content-Type-Options "nosniff" always;
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
add_header Permissions-Policy "geolocation=(), microphone=(), camera=()" always;
```

---

## Risk Assessment

### Overall Risk Matrix

| Vulnerability | Likelihood | Technical Impact | Business Impact | Overall Risk |
|--------------|------------|------------------|-----------------|--------------|
| Clickjacking | Medium | Medium | Medium | **MEDIUM** |
| Directory Listing | High | High | High | **HIGH** |
| Missing Headers | High | Low-Medium | Low-Medium | **MEDIUM** |

### Risk Calculation Methodology

**Likelihood Factors:**
- Ease of exploitation
- Required attacker skill level
- Availability of exploitation tools
- Public knowledge of vulnerability

**Impact Factors:**
- Data confidentiality breach
- System integrity compromise
- Service availability
- Regulatory compliance
- Reputation damage

### Business Impact Analysis

**Immediate Impacts:**
- Unauthorized information disclosure
- Potential data breach
- Compliance violations

**Long-term Impacts:**
- Loss of public trust
- Regulatory fines
- Legal consequences
- Reputation damage

---

## Remediation Roadmap

### Phase 1: Immediate (Within 24-48 hours)

**Priority: CRITICAL**

1. ✅ Disable directory listing on all web servers
2. ✅ Implement X-Frame-Options header
3. ✅ Review and remove/relocate sensitive files from web root

### Phase 2: Short-term (Within 1 week)

**Priority: HIGH**

1. ✅ Implement comprehensive security headers
2. ✅ Conduct full web server configuration audit
3. ✅ Review access controls on all directories
4. ✅ Implement monitoring for similar misconfigurations

### Phase 3: Medium-term (Within 1 month)

**Priority: MEDIUM**

1. ✅ Comprehensive penetration testing
2. ✅ Security awareness training for development team
3. ✅ Implement Web Application Firewall (WAF)
4. ✅ Establish secure development lifecycle

### Phase 4: Long-term (Ongoing)

**Priority: CONTINUOUS**

1. ✅ Regular security assessments
2. ✅ Vulnerability scanning and patch management
3. ✅ Security monitoring and incident response
4. ✅ Compliance audits and reviews

---

## Appendix

### A. Testing Tools & Versions

- **Burp Suite:** Community Edition 2024.x
- **Browser:** Google Chrome/Mozilla Firefox (Latest)
- **Operating System:** Windows 10/Kali Linux

### B. References

1. OWASP Testing Guide v4
2. OWASP Top 10 - 2021
3. CWE/SANS Top 25 Most Dangerous Software Errors
4. NIST Cybersecurity Framework
5. PCI DSS Requirements

### C. Glossary

**Clickjacking:** Attack where user clicks on concealed element  
**Directory Listing:** Server misconfiguration exposing file structure  
**CSP:** Content Security Policy - Security header  
**CVSS:** Common Vulnerability Scoring System  
**OWASP:** Open Web Application Security Project  

### D. Contact Information

**For Questions or Clarifications:**

Raja R  
Security Researcher  
Email: leviraja670@gmail.com  
LinkedIn: linkedin.com/in/rajar219  

---

**Report Classification:** Responsible Disclosure  
**Discovery Date:** January 25, 2020  
**Report Date:** January 2025  
**Last Updated:** January 2025  
**Version:** 1.0

---

*This report is provided for security improvement purposes only. All information should be kept confidential and used solely for remediation efforts.*
