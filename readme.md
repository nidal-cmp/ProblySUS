# Problysus - Scam Detection Web App

Problysus is a full-stack web application designed to analyze website URLs for potential scam risks. It provides a comprehensive risk assessment by performing multiple checks, including blacklist verification, domain age analysis, SSL certificate validation, and content trust verification.

## Key Features

- **Real-time URL Analysis**: Instantly scans URLs to detect potential threats.
- **Risk Scoring**: Calculates a risk score (0-100) and classifies sites as Safe, Suspicious, or Fraudulent.
- **Detailed Checks**:
  - **Blacklist Check**: Verifies if the domain is present in known threat intelligence feeds.
  - **WHOIS Analysis**: Checks domain age and creation date.
  - **SSL/HTTPS Verification**: Ensures the site uses a valid security certificate.
  - **Pattern Recognition**: Detects suspicious URL patterns often used in phishing.
  - **Content Trust**: Scans for essential trust indicators like Privacy Policy and Contact pages.

## Performance Optimizations

The scanner includes several performance optimizations to speed up analysis:

### Fast Mode
Use `?fast=true` query parameter for quicker scans that skip behavior analysis:
```
POST /analyze?fast=true
{
  "url": "https://example.com"
}
```

**Fast Mode vs Full Analysis:**
- **Fast Mode**: ~3-5 seconds (skips Playwright browser analysis)
- **Full Analysis**: ~8-12 seconds (includes all checks)

### Caching
- WHOIS data cached for 24 hours
- DNS records cached per session
- Reduces repeated lookups for same domains

### Timeout Optimizations
- WHOIS lookups: 5 second timeout
- DNS lookups: 3 second timeout per query
- HTTP requests: 5 second timeout
- Playwright browser: 6 second total timeout

### Parallel Processing
- Independent checks run concurrently where possible
- HTML content fetched once and reused across multiple analyzers

## Tech Stack

**Backend**
- Python
- Flask (Web Framework)
- `requests`, `python-whois` (Analysis Tools)

**Frontend**
- React (via Vite)
- Framer Motion (Animations)
- Axios (API Communication)

## Installation

### Prerequisites
- Python 3.8+
- Node.js & npm

### Backend Setup

1. Navigate to the backend directory:
   ```bash
   cd backend
   ```

2. Create a virtual environment:
   ```bash
   python -m venv venv
   ```

3. Activate the virtual environment:
   - Windows:
     ```bash
     venv\Scripts\activate
     ```
   - macOS/Linux:
     ```bash
     source venv/bin/activate
     ```

4. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

### Frontend Setup

1. Navigate to the frontend directory:
   ```bash
   cd frontend
   ```

2. Install dependencies:
   ```bash
   npm install
   ```

## How to Run

1. **Start the Backend Server**:
   From the `backend` directory (with venv activated):
   ```bash
   python app.py
   ```
   The backend will start on `http://127.0.0.1:5000`.

2. **Start the Frontend Development Server**:
   From the `frontend` directory:
   ```bash
   npm run dev
   ```
   Open the URL shown in the terminal (usually `http://localhost:5173`) to use the application.
