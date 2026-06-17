# SentryCode // AI Vulnerability Scanner & Auditor

SentryCode is a high-fidelity, interactive developer dashboard designed to audit source code repositories for vulnerabilities, secret leaks, and OWASP Top 10 violations. 

This repository contains the interactive frontend experience for simulating static analysis sweeps, analyzing vulnerable code syntax trees, and applying simulated AI auto-remediation fixes in real-time.

---

## 🚀 Key Features

* **Sleek IDE Dashboard**: Premium dark-mode developer UI built with glassmorphism aesthetics, glowing severity meters, and a responsive flex/grid structure.
* **Interactive Drag-and-Drop Zone**: Drop single code files or `.zip` archives, or paste your GitHub repository link to begin auditing.
* **Simulated Auditor Terminal**: Live circular progress tracking accompanied by step-by-step console logging that details syntax tree parsing, control flow graph audits, and rule triggers.
* **Color-Coded Findings Feed**: Filter scan issues instantly by risk levels (High, Medium, Low, or Fixed).
* **Side-by-Side Code Diffs**: Interactive cards expand to reveal a comparison between **Vulnerable Code** (red highlights) and the **Secure Remediation Fix** (green highlights) with custom explanations.
* **One-Click Auto-Remediation**: Click "Apply Remediation Fix" to instantly deploy a patch, update status badges, and dynamically recalculate the overall security baseline score.

---

## 🛠️ Technology Stack

* **Structure**: Semantic HTML5 markup
* **Styling**: Vanilla CSS3 (custom CSS variables, CSS grid/flexbox, keyframe animations, glassmorphism filters)
* **Logic**: Vanilla ES6 JavaScript (simulated logging engines, state tracking, and document object manipulation)
* **Icons & Fonts**: FontAwesome v6.4, Google Fonts (Outfit & Fira Code)

---

## 💻 Running Locally

Since the application runs entirely in the client-side browser, you can run it without any complex build steps.

### Method 1: Using Node's Static Server (Recommended)
Navigate to the directory and run:
```bash
npx serve .
```
Open **`http://localhost:3000`** in your browser.

### Method 2: Python HTTP Server
Run the local python server module:
```bash
python -m http.server 8000
```
Open **`http://localhost:8000`** in your browser.

### Method 3: Direct File Execution
Double-click `index.html` in your directory to run the application directly from the local file system.

---

## 🔍 Pre-configured Audit Demos
Click on either **`vuln-flask-ecommerce.zip`** (Flask/SQL Injection) or **`node-auth-service-v3.zip`** (Express/Secrets leak) in the sidebar setup panel to instantly execute a sample scan.
