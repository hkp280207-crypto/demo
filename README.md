# 🛡️ Final Project — Cyber Crime Reporting System & NexusHire Job Portal

This repository contains two independent mini-projects built as part of a Full Stack Development course:

1. **Cyber Crime Reporting System** — a Python/Streamlit web application
2. **NexusHire** — a front-end job portal built in HTML, CSS, and JavaScript

---

## 📁 Project Structure

```
final project/
├── cybercrime.py               # Python Streamlit application
├── cybercrime_data.json        # JSON database (auto-generated on first run)
├── nexushire_updated_fixed.html # NexusHire front-end job portal
├── fsd final ppt.pptx          # Full Stack Development project presentation
└── python ppt c8.pptx          # Python syllabus presentation (Chapter 8)
```

---

## 🔐 Project 1: Cyber Crime Reporting System

A full-featured web application for reporting and managing cyber crimes, built with **Python** and **Streamlit**.

### Features

- **User Registration & Login** with CAPTCHA verification
- **Forgot Password** flow with CAPTCHA-based identity verification
- **Forgot Email** recovery using name or mobile number
- **Complaint Filing** with automatic severity assignment based on crime type
- **Case Priority Algorithm** — scores cases using severity, evidence, time pending, and financial loss
- **Google Maps integration** — latitude/longitude location tagging for complaints
- **Admin Panel** — view all complaints with full user details, assign officers and police stations, update complaint status
- **Analytics Dashboard** — charts for status distribution, crime type breakdown, and severity analysis
- **Sequential Complaint IDs** — formatted as `CYB-YYYY-NNNNNN`
- **Police Officer ID generation** — auto-generated `POL-XXXXX` IDs for admins
- **Cyber Safety Tips** section for citizens

### Tech Stack

| Tool | Purpose |
|------|---------|
| Python 3.x | Core language |
| Streamlit | Web UI framework |
| Pandas & NumPy | Data handling |
| Plotly | Interactive charts |
| hashlib | Password hashing (SHA-256) |
| JSON | Persistent local storage |
| datetime | Timestamps and CAPTCHA expiry |
| random & string | CAPTCHA generation |

### Python Concepts Demonstrated

- Dataclasses (`@dataclass`) for `User` and `Complaint` models
- Type hints and `Optional` typing
- SHA-256 password hashing
- Regular expressions for email, mobile, and password validation
- `random.choice()` and `random.randrange()` for CAPTCHA and ID generation
- `datetime` module for timestamps and expiry logic
- `Counter` from `collections` for analytics
- `reduce` from `functools`
- JSON file I/O for a lightweight database
- Weighted priority formula using constants

### Installation & Setup

1. **Install dependencies:**
   ```bash
   pip install streamlit pandas numpy plotly
   ```

2. **Run the app:**
   ```bash
   streamlit run cybercrime.py
   ```

3. **Default Admin credentials:**
   - Email: `lj@gmail.com`
   - Password: `Admin@123`

> ⚠️ A CAPTCHA will be displayed on-screen during login and registration. Enter it to proceed.

### Crime Types & Auto-Assigned Severity

| Crime Type | Severity (1–10) |
|---|---|
| Data Breach | 10 |
| Ransomware | 10 |
| Hacking | 9 |
| Identity Theft | 9 |
| Online Fraud | 8 |
| Phishing | 7 |
| Cyberbullying | 6 |
| Social Media Crime | 5 |

### Priority Score Formula

```
Priority = (Severity × 0.4) + (Evidence × 0.3) + (Time Pending × 0.2) + (Financial Loss × 0.1)
```

Scores map to: 🔴 CRITICAL (≥8) · 🟠 HIGH (≥6) · 🟡 MEDIUM (≥4) · 🟢 LOW (<4)

---

## 💼 Project 2: NexusHire — Job Portal

A responsive, single-page job portal front-end built entirely in **HTML, CSS, and vanilla JavaScript** — no frameworks required.

### Features

- **Job Listings** — searchable and filterable grid of job cards
- **Advanced Filters** — filter by schedule (Full-Time / Part-Time), salary type, experience level, work mode (Remote / Hybrid / Onsite), and budget range
- **Real-time Search** — instant filtering by job title, skills, or company name
- **User Authentication** — modal-based login and registration with client-side validation
- **User Dashboard** — profile section with avatar upload
- **My Jobs** — track jobs the user has applied to
- **Toast Notifications** — lightweight feedback messages
- **Responsive Design** — mobile-friendly layout using CSS variables and flexbox

### Tech Stack

- HTML5
- CSS3 (custom properties, flexbox, responsive design)
- Vanilla JavaScript (DOM manipulation, event handling, client-side filtering)
- Google Fonts (Sora)
- Font Awesome icons

### How to Run

Simply open `nexushire_updated_fixed.html` in any modern web browser — no server or installation needed.

```bash
# On macOS
open nexushire_updated_fixed.html

# On Linux
xdg-open nexushire_updated_fixed.html

# On Windows
start nexushire_updated_fixed.html
```

---

## 👥 Roles

| Role | Access |
|---|---|
| **Citizen** | Register, log in, file complaints, view own complaints, read safety tips |
| **Admin** | View all complaints with user details, assign officers and stations, update statuses, view analytics |

---

## 📌 Notes

- The `cybercrime_data.json` file is auto-created on first run and stores all users and complaints locally.
- CAPTCHA codes are displayed on-screen (not sent via email) and expire after 5 minutes.
- The NexusHire portal is purely front-end; no backend or database is connected.