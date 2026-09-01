# 🚀 SentinelGuard — OCI Production & CI/CD Deployment Guide

This guide covers complete automated **Continuous Integration & Continuous Deployment (CI/CD)** with GitHub Actions to your Oracle Cloud Infrastructure (OCI) Free Tier VM (`140.245.250.50`) pointing to your subdomain `usertesting.singamsettikrishna.in`.

---

## 🛠️ Architecture Overview

```
[Git Push: main]
       │
       ▼
[GitHub Actions CI/CD]
   ├─ 1. Build & Test (Java 21 Maven, WAF exploit suites)
   ├─ 2. Package Executable JAR
   └─ 3. SSH into OCI VM (140.245.250.50)
            │
            ▼
    [OCI Compute Instance]
       ├─ Git Pull / Reset to latest main
       ├─ Docker Compose Build & Up (Zero-Downtime)
       ├─ Automated Gateway Health Check Probe
       └─ Nginx Reverse Proxy (SSL Termination -> Port 8090)
```

---

## Step 1: Configure GitHub Repository Secrets

In your GitHub repository (`https://github.com/<your-username>/sentinel-guard`), navigate to:
👉 **Settings** &rarr; **Secrets and variables** &rarr; **Actions** &rarr; **New repository secret**.

Add the following 4 secrets:

| Secret Name | Value | Description |
|---|---|---|
| `OCI_HOST` | `140.245.250.50` | Your OCI VM Public IPv4 Address |
| `OCI_USERNAME` | `opc` | Your OCI VM SSH Username |
| `OCI_SSH_KEY` | *(Contents of your private key)* | Entire text of `ssh-key-2026-09-01.key` (including `-----BEGIN ... -----` and `-----END ... -----`) |
| `OCI_SSH_PORT` | `22` | SSH Port (default `22`) |
| `OCI_APP_DIR` | `/home/opc/sentinel-guard` | Target deployment directory on the VM |

> 💡 **Tip to copy private key content**:
> In WSL/PowerShell, run:
> ```bash
> cat ~/.ssh/ssh-key-2026-09-01.key
> ```
> Copy the output and paste it into `OCI_SSH_KEY`.

---

## Step 2: One-Time OCI Server Setup

SSH into your OCI instance:
```bash
ssh -i ~/.ssh/ssh-key-2026-09-01.key opc@140.245.250.50
```

### 1. Enable Docker & User Permissions
```bash
sudo systemctl enable --now docker
sudo usermod -aG docker opc
```

### 2. Configure Nginx Reverse Proxy
Place the reverse proxy configuration:
```bash
sudo tee /etc/nginx/conf.d/usertesting.conf << 'EOF'
server {
    listen 80;
    server_name usertesting.singamsettikrishna.in;

    location / {
        proxy_pass http://127.0.0.1:8090;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
EOF

sudo nginx -t && sudo systemctl reload nginx
```

### 3. Generate Free Let's Encrypt SSL
```bash
sudo certbot --nginx -d usertesting.singamsettikrishna.in --non-interactive --agree-tos -m krishna@singamsettikrishna.in
sudo systemctl reload nginx
```

---

## Step 3: Trigger Automated CI/CD Pipeline

Whenever you push to the `main` branch, GitHub Actions will automatically:
1. Compile, run unit and exploit tests using Java 21 & Maven.
2. Connect securely over SSH to your OCI VM.
3. Pull the newest changes, run `docker compose up -d --build`.
4. Run an automated HTTP health probe against `/api/traffic/ping` to verify successful startup.

To test the deployment manually from your local machine:
```powershell
cd E:\PracticeProjects\sentinel-guard
git add .
git commit -m "ci: add automated GitHub Actions workflow for OCI deployment"
git push origin main
```

---

## Step 4: Live Verification & Testing

1. **Dashboard URL**: [https://usertesting.singamsettikrishna.in](https://usertesting.singamsettikrishna.in)
2. **Pre-configured Accounts**:
   - **Super Admin**: `krishna` / `krishna`
   - **Security Analyst**: `alex` / `alex`
   - **Auditor**: `sarah` / `sarah`

3. **Simulate External Attack to Test WAF & Real-Time Telemetry**:
```bash
# SQL Injection Test (Blocked 403)
curl -i "https://usertesting.singamsettikrishna.in/api/products?id=1'%20OR%201=1--"

# Remote Code Execution Probe (Blocked 403)
curl -i "https://usertesting.singamsettikrishna.in/api/status?cmd=;cat%20/etc/passwd"

# Cross-Site Scripting (Blocked 403)
curl -i -X POST "https://usertesting.singamsettikrishna.in/api/contact" -d "msg=<script>alert('XSS')</script>"
```
