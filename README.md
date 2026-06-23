# SentryCode // AI Vulnerability Scanner & Auditor

SentryCode is a high-fidelity, interactive developer dashboard designed to audit source code repositories for vulnerabilities, secret leaks, and OWASP Top 10 violations. 

### 🌐 Live Demo: [https://sanondika5-sketch.github.io/VulnerabilityScanner/](https://sanondika5-sketch.github.io/VulnerabilityScanner/)

This repository contains the interactive frontend experience for simulating static analysis sweeps, analyzing vulnerable code syntax trees, applying simulated AI auto-remediation fixes in real-time, and reviewing local scan logs.

---

## 🚀 Key Features

*   **Sleek IDE Dashboard**: Premium dark-mode developer UI built with glassmorphism aesthetics, glowing severity meters, and a responsive layout.
*   **Interactive Drag-and-Drop Zone**: Drop single code files or `.zip` archives, or paste your GitHub repository link to begin auditing.
*   **Simulated Auditor Terminal**: Live progress tracking accompanied by step-by-step console logging detailing syntax tree parsing, control flow audits, and rule triggers.
*   **Dynamic Security Score Engine**: The application calculates scores dynamically, starting from `100/100` and deducting points based on active (unresolved) findings. Remediating findings dynamically increases the score in real-time.
*   **Audit Scan History Log**: A functional Scan History page records and displays recent scans, their date/time, security scores, and severity indicators. Users can click **View Audit** to inspect any recorded audit.
*   **Color-Coded Findings Feed**: Filter scan issues instantly by risk levels (High, Medium, Low, or Fixed).
*   **Side-by-Side Code Diffs**: Interactive cards expand to reveal a comparison between **Vulnerable Code** (red highlights) and the **Secure Remediation Fix** (green highlights) with custom explanations.
*   **One-Click Auto-Remediation**: Click "Apply Remediation Fix" to instantly deploy a patch, update status badges, and dynamically recalculate the overall security baseline score.
*   **Client-Side PDF Exports**: Fully functional client-side PDF generation via the `jsPDF` library. Clicking "Download PDF" generates a structured audit report summarizing scores, metadata, and detailed vulnerability listings.

---

## 🛠️ Technology Stack

*   **Structure**: Semantic HTML5 markup
*   **Styling**: Vanilla CSS3 (custom CSS variables, CSS grid/flexbox, keyframe animations, glassmorphism filters)
*   **Logic**: Vanilla ES6 JavaScript (simulated logging engines, state tracking, and document object manipulation)
*   **PDF Generation**: jsPDF v2.5.1
*   **Icons & Fonts**: FontAwesome v6.4, Google Fonts (Outfit & Fira Code)

---

## 💻 Running 

Here is the final live production URL hosted on Vercel: 👉 https://frontend-nine-rho-vrlpnl0iuk.vercel.app

ℹ️ How It Works:
Frontend (Vercel): Deployed to Vercel and points directly to the backend API/WebSocket address.
Backend (Local + Tunnel): Running on your machine (port 5000) and exposed via a stable, persistent localtunnel subdomain:
Backend URL: https://appshield-sanondika.loca.lt
---

## 🔍 Pre-configured Audit Demos
Click on either **`vuln-flask-ecommerce.zip`** (Flask/SQL Injection) or **`node-auth-service-v3.zip`** (Express/Secrets leak) in the sidebar setup panel to instantly execute a sample scan with dynamic scoring and custom terminal logging timelines.
