# Local Laya AI Migration & Setup Guide

## 1. Overview & Architecture Changes
This project has migrated from the external **Google Gemini REST API** to **Local Laya AI** (`convaiinnovations/laya`), an open-weight, non-autoregressive System 1 decision engine developed by Nandha Kishor M (Apache 2.0).

### Key Architectural Decisions:
- **Zero External API Dependencies:** The application no longer requires a Google Gemini API key or any paid external cloud AI subscriptions. All inference executes locally on the host machine.
- **Microservices Bridge Architecture:**
  - **Frontend:** React 19 + Vite dashboard remains unchanged in UI appearance and styling.
  - **Local AI Backend:** A lightweight FastAPI service (`backend/service.py`) running on `http://127.0.0.1:8000` manages the Laya `Router` instance and handles model inference requests.
  - **Vite Proxy:** Configured in `vite.config.js` to seamlessly route `/api/*` calls from the browser to the local Python service without CORS issues.
  - **Graceful Fallback:** If the local Python service is offline, the frontend logs a clear advisory and falls back to deterministic calibrated Open FAIR baseline findings without crashing.
- **Reliable Actuarial Risk Scoring:**
  - Laya's non-autoregressive decision heads (`choice`, `score`, `noul`) are used for domain classification (`internal`, `external`, `machines`), severity triage (`Severe`, `Medium`, `Ignorable`), recommendation actions, and exploitability/compliance likelihood.
  - Numerical risk calculations (`lossIfIgnored`, `solutionCost`, `netSavings`) remain **strictly deterministic** based on validated Open FAIR standards (ANSI/O-RA), preventing AI hallucination or arbitrary financial metrics.

---

## 2. Verified Laya Installation & Technical Specifications
- **Official GitHub:** [https://github.com/NandhaKishorM/laya](https://github.com/NandhaKishorM/laya)
- **Local Guide:** [https://laya.tools/guides/run-laya-locally](https://laya.tools/guides/run-laya-locally)
- **Model Checkpoint:** `convaiinnovations/laya` (ModernBERT-large, ~421M parameters, ~847 MB weights)
- **Supported Python Versions:** Python 3.10 to Python 3.14 (Verified on Python 3.13.1 64-bit on Windows 11)
- **Installed Packages:**
  - `laya==0.4.1`
  - `torch==2.14.1`
  - `transformers==5.19.0`
  - `fastapi==0.143.0`
  - `uvicorn==0.54.0`
  - `pydantic==2.14.0`

---

## 3. Required Software & Hardware
### Software Requirements:
- **Windows 10 / 11 (64-bit)**
- **Python 3.10+** (Python 3.13 recommended)
- **Node.js 18+** & npm

### Hardware Requirements:
- **RAM:** Minimum 4 GB available system memory (~1.5 GB resident memory during Laya forward pass).
- **Disk Space:** ~2.5 GB free disk space (for Python virtual environment and Hugging Face model cache).
- **Compute:** Standard x86_64 CPU (multi-core Intel/AMD). Dedicated GPU (NVIDIA CUDA or Intel XPU) is optional; CPU inference executes in ~1.2s to 1.5s per forward pass.

---

## 4. Exact Windows PowerShell Setup Commands

### Step 1: Create the Isolated Virtual Environment
Open **Windows PowerShell** in the project directory (`c:\Users\priya\lowkeyreports2`):

```powershell
# Create dedicated virtual environment using Python 3.13
py -3.13 -m venv .venv_laya

# Verify virtual environment
.\.venv_laya\Scripts\python.exe --version
```

### Step 2: Install Dependencies
```powershell
# Install Laya and backend requirements
.\.venv_laya\Scripts\python.exe -m pip install -r backend\requirements.txt

# Verify Laya import
.\.venv_laya\Scripts\python.exe -I -c "import laya; print(f'Laya version: {laya.__version__}')"
```

---

## 5. Starting the Application

The application consists of two processes running locally:

### Option A: Using NPM Scripts (Recommended)

1. **Terminal 1: Start the Local Laya AI Service**
   ```powershell
   npm run start:laya
   ```
   *The service will start on `http://127.0.0.1:8000`. You should see `Local Laya Router successfully initialized.`*

2. **Terminal 2: Start the Frontend Application**
   ```powershell
   npm run dev
   ```
   *Open `http://localhost:5173` in your browser.*

### Option B: Manual Commands

1. **Terminal 1: Start Backend**
   ```powershell
   .\.venv_laya\Scripts\python.exe -m uvicorn backend.service:app --host 127.0.0.1 --port 8000 --reload
   ```

2. **Terminal 2: Start Frontend**
   ```powershell
   npm run dev
   ```

---

## 6. How to Test the Integration

### 1. Automated API Endpoint Tests (Integration Tests)
Run the full test suite covering `/api/health`, `/api/classify`, input validation (empty/malformed payloads), and `/api/quantify` schema validation:

```powershell
npm run test:laya
# OR
.\.venv_laya\Scripts\python.exe tests\test_api_endpoints.py
```
**Expected Result:** 5 tests pass (`OK`).

### 2. Empirical Model Evaluation Benchmark
Run the reproducible test dataset evaluation containing 11 cybersecurity scenarios across phishing, ransomware, exposed services, unpatched vulnerabilities, and insecure configurations:

```powershell
npm run eval:laya
# OR
.\.venv_laya\Scripts\python.exe tests\evaluate_laya.py
```

### 3. Verification of Health Endpoint
In PowerShell or browser:
```powershell
Invoke-RestMethod -Uri "http://127.0.0.1:8000/api/health"
```
**Output:**
```json
{
  "status": "healthy",
  "engine": "Local Laya AI",
  "model": "convaiinnovations/laya",
  "architecture": "Non-Autoregressive Decision Engine (ModernBERT-large)",
  "device": "cpu",
  "ready": true,
  "supportedQuestionTypes": ["choice", "score", "noul"]
}
```

---

## 7. Measured Benchmark Results
Evaluated on `tests/test_dataset.json` (11 representative enterprise scenarios):

| Metric | Measured Value | Notes |
|---|---|---|
| **Domain Classification Accuracy** | **81.8%** (9/11) | Strong zero-shot categorization across internal, external, machines |
| **Severity Classification Accuracy** | **45.5%** (5/11) | Uncalibrated zero-shot weights; deterministic FAIR ranges preserve consistency |
| **Active Exploit Detection (Likelihood)** | **0.76 – 0.89** | Correctly detects high active exploit probability on LockBit & RCE CVEs |
| **Benign / Staging Exploit Likelihood** | **0.07 – 0.09** | Accurately identifies low exploit probability on isolated internal assets |
| **Average Decision Latency (CPU)** | **~1.4s** | First forward pass downloads/caches weights; subsequent runs are fast |

---

## 8. Files Changed Summary

1. **`backend/service.py`** *(New)*: FastAPI service providing local Laya model inference (`/api/health`, `/api/classify`, `/api/quantify`).
2. **`backend/requirements.txt`** & **`requirements.txt`** *(New)*: Pinned Python dependencies (`laya`, `torch`, `transformers`, `fastapi`, `uvicorn`, `pydantic`).
3. **`backend/run_service.ps1`** *(New)*: PowerShell launcher script for the local Laya inference engine.
4. **`tests/test_dataset.json`** *(New)*: Reproducible evaluation dataset with labeled cybersecurity scenarios.
5. **`tests/evaluate_laya.py`** *(New)*: Evaluation benchmark script measuring accuracy, latency, and confusion metrics.
6. **`tests/test_api_endpoints.py`** *(New)*: Integration tests verifying endpoints, error handling, and output schemas.
7. **`vite.config.js`** *(Modified)*: Removed Gemini API key defines; added Vite proxy for `/api` routing to `http://127.0.0.1:8000`.
8. **`.env`** *(Modified)*: Removed `GEMINI_API_KEY` and `VITE_GEMINI_API_KEY`; configured `VITE_LAYA_API_URL=http://127.0.0.1:8000`.
9. **`src/utils/vulnerabilityFetcher.js`** *(Modified)*: Replaced Google Gemini REST calls with calls to Local Laya AI (`/api/quantify`) and graceful fallback.
10. **`src/utils/zipParser.js`** *(Modified)*: Updated docstrings, comments, and sample zip manifest text to reference Local Laya AI.
11. **`src/components/Header.jsx`** *(Modified)*: Updated engine badge to `ENGINE: LOCAL LAYA AI (v0.4.1)`.
12. **`src/components/ProcessingView.jsx`** *(Modified)*: Updated processing pipeline logs and header to reference Local Laya AI.
13. **`src/components/UploadView.jsx`** *(Modified)*: Updated subheadline text to reference Local Laya AI.
14. **`src/components/Footer.jsx`** *(Modified)*: Updated footer attribution to Local Laya AI.
15. **`src/components/DashboardView.jsx`** *(Modified)*: Updated executive summary text to Local Laya AI Actuarial Core.
16. **`src/utils/pdfGenerator.js`** *(Modified)*: Updated PDF audit header and executive summary descriptions.
17. **`package.json`** *(Modified)*: Added `start:laya`, `test:laya`, and `eval:laya` scripts.
18. **`.gitignore`** *(Modified)*: Added `.venv*`, `__pycache__`, and `models/`.

---

## 9. Known Limitations & Production Deployment Notes
1. **Laya Model Characteristics:**
   - Laya is a **non-autoregressive decision engine** (predicts typed answers over choice, score, and binary noul questions). It is *not* an autoregressive generative model (it does not generate arbitrary markdown or conversational chat).
   - Findings use calibrated enterprise threat narratives and MITRE ATT&CK vectors, classified and triaged dynamically by Laya.
2. **Localhost Scope:**
   - The model runs locally on your Windows laptop on `127.0.0.1:8000`.
   - If the application is built and hosted publicly on a web server (e.g. Vercel, AWS S3, Netlify), users will not have access to your laptop's localhost.
   - For public deployment, host the Python FastAPI service on a cloud container (e.g. Docker, AWS ECS, GCP Cloud Run, or a Linux VM) and set `VITE_LAYA_API_URL` to that server's URL. Do **not** revert to Gemini.
3. **Windows Symlink Warning:**
   - Hugging Face Hub prints an advisory about symlinks on Windows if Developer Mode is not enabled. This warning is completely harmless; model files are cached and loaded properly in `.cache\huggingface\hub`.
