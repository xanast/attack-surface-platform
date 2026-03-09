# Attack Surface Platform

A defensive web security monitoring platform for analyzing the exposure of authorized targets.

This project provides a simple attack surface management dashboard where users can add domains, run security scans, and review risk indicators such as security headers, TLS configuration, open ports, technologies, and discovered subdomains.

The goal of the project is to demonstrate practical experience with backend development, security tooling, and web application architecture.

---

# Dashboard Preview

![Dashboard](assets/dashboard.png)

---

# Features

• Target management (add domains to monitor)  
• Automated security scans  
• HTTP security headers analysis  
• TLS configuration inspection  
• Open port discovery  
• Basic technology fingerprinting  
• Subdomain discovery  
• Risk scoring engine  
• Security findings generation  
• Scan history storage  
• Web dashboard interface

---

# Technology Stack

Backend  
• Python  
• FastAPI  

Database  
• SQLite  
• SQLAlchemy ORM  

Frontend  
• HTML  
• Jinja Templates  
• CSS  

Networking / Security  
• HTTPX  
• SSL / Socket scanning  

---

# Project Structure

attack-surface-platform
│
├── app
│ ├── db
│ ├── models
│ ├── routes
│ ├── services
│ ├── static
│ └── templates
│
├── assets
│ └── dashboard.png
│
├── attack_surface.db
├── requirements.txt
└── README.md


---

# Installation

Clone the repository
git clone https://github.com/xanast/attack-surface-platform.git


Enter the project
cd attack-surface-platform

Create virtual environment
python -m venv venv

Activate environment

Mac / Linux
source venv/bin/activate

Install dependencies
pip install -r requirements.txt

Run the application
uvicorn app.main:app --reload

Open the dashboard ( Follow the link etc)

---

# Example Workflow

1. Add a domain target  
2. Run a security scan  
3. Review the generated findings  
4. Inspect detected technologies and open ports  
5. Evaluate the calculated risk score

---

# Security Notice

This tool is intended **only for authorized security testing and defensive analysis**.

Do not scan systems without permission.

---

# Future Improvements

• background scanning workers  
• scheduled scans  
• improved risk scoring model  
• vulnerability database integration  
• API endpoints  
• authentication system  
• scan visualization charts

---

# Author

Anastasios Makrygiannis

Computer Science student focused on backend development, security tooling, and networking.

GitHub  
https://github.com/xanast