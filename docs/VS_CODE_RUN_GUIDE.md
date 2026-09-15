# SAHE Cloud IDS/IPS — Complete VS Code Run Guide

This guide explains how to open, configure, test, and run the complete project from the final ZIP archive. It covers the backend, frontend dashboard, optional MongoDB/Docker stack, benchmark analysis, and the real CICIDS2017 ML workflow.

## 1. What you need before starting

Install the following software on your computer:

| Software | Recommended version | Purpose |
|---|---:|---|
| Visual Studio Code | Current stable release | Edit and run the project |
| Python | 3.11 or 3.12 | FastAPI backend, ML, cryptography, tests |
| Node.js | 20 or newer | React/Vite dashboard |
| Git | Current stable release | Optional, useful for source control |
| Docker Desktop | Current stable release | Optional; runs MongoDB, backend, and frontend together |
| MongoDB | 6 or newer | Optional if you do not use Docker |

The project does not include MongoDB, the CICIDS2017 dataset, trained ML models, or real secrets. Those must be supplied locally when you want real ML or persistent database execution.

## 2. Extract the ZIP archive

Download the final archive and extract it. After extraction, the important directory is:

```text
sahe-cloud-ids/
```

Do not open the ZIP itself as the project folder. Extract it first.

### Windows

1. Right-click `sahe-cloud-ids-final-complete.zip`.
2. Select **Extract All**.
3. Choose a convenient location such as `Documents`.
4. Open the extracted `sahe-cloud-ids` folder.
5. Right-click inside the folder and select **Open with Code**, or open VS Code and choose **File → Open Folder**.

### macOS or Linux

Open a terminal in the directory containing the ZIP and run:

```bash
unzip sahe-cloud-ids-final-complete.zip
cd sahe-cloud-ids
code .
```

If the `code` command is not available, open VS Code manually and use **File → Open Folder**.

## 3. Inspect the project in VS Code

The root folder should contain these directories and files:

```text
backend/                 FastAPI service
crypto/                  AES-GCM, X25519, RSA-OAEP, Ed25519, SAHE
experiments/             Benchmark inputs, scripts, and results
frontend/                React + Vite dashboard
ml/                      CICIDS2017 preprocessing and model training
firewall/                Firewall abstractions
 tests/                  Core unit tests
docs/                    Architecture and methodology
.env.example             Root configuration template
docker-compose.yml       Optional three-service deployment
```

Recommended VS Code extensions are **Python**, **Pylance**, **ESLint** or an equivalent JavaScript linter, and **Docker** if you intend to use Docker Desktop.

## 4. Create and activate the Python virtual environment

Open the VS Code integrated terminal with **Terminal → New Terminal**.

### Windows PowerShell

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r backend\requirements.txt
```

If PowerShell blocks activation, run PowerShell as your normal user and execute this once:

```powershell
Set-ExecutionPolicy -Scope CurrentUser RemoteSigned
```

Then activate the environment again.

### macOS or Linux

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r backend/requirements.txt
```

In VS Code, press `Ctrl+Shift+P` or `Cmd+Shift+P`, select **Python: Select Interpreter**, and choose the interpreter inside `.venv`.

## 5. Create the local environment file

From the project root, copy the example file:

### Windows PowerShell

```powershell
Copy-Item .env.example .env
```

### macOS or Linux

```bash
cp .env.example .env
```

Open `.env` and review the values. For the safe local default, keep:

```dotenv
MONGODB_URI=mongodb://localhost:27017
MONGODB_DB_NAME=sahe_ids
FIREWALL_MODE=simulated
CORS_ALLOWED_ORIGINS=http://localhost:5173,http://127.0.0.1:5173
```

For protected crypto and firewall endpoints, set a local development token. Do not commit it or share it publicly:

```dotenv
API_AUTH_TOKEN=replace-with-a-long-random-local-value
```

The application is intentionally fail-closed when this token is missing.

## 6. Run the backend without Docker

Keep the Python virtual environment activated. From the project root, run:

```bash
python -m uvicorn backend.app.main:app --reload --host 127.0.0.1 --port 8000
```

On Windows PowerShell, the same command works after the virtual environment is activated.

Open these URLs in a browser:

- API health: <http://127.0.0.1:8000/health>
- Swagger API documentation: <http://127.0.0.1:8000/docs>
- OpenAPI JSON: <http://127.0.0.1:8000/openapi.json>

Expected health behavior is a JSON response indicating that the API is running. If MongoDB is not running, the service may use its documented in-memory fallback for applicable endpoints and identify that backend in responses.

Stop the backend with `Ctrl+C`.

## 7. Run the React dashboard without Docker

Open a second VS Code terminal. Leave the backend terminal running.

```bash
cd frontend
npm install
npm run dev -- --host 127.0.0.1
```

Open <http://127.0.0.1:5173> in your browser. The dashboard calls the backend at its configured API base URL. If the dashboard does not reach the backend, check that:

1. The backend is running on port 8000.
2. The frontend is running on port 5173.
3. `CORS_ALLOWED_ORIGINS` in `.env` includes `http://127.0.0.1:5173`.
4. No other application is already using either port.

Stop the frontend with `Ctrl+C`.

## 8. Run the automated tests

From the project root, with the Python virtual environment activated:

```bash
python -m pytest -q
```

The cumulative project previously reported 212 passing tests. The exact count can change if dependencies or source files change. Treat the current command output as authoritative.

Backend-only tests can be run with:

```bash
python -m pytest backend/tests -q
```

Crypto, preprocessing, severity, training, and evaluation tests can be run with:

```bash
python -m pytest tests -q
```

## 9. Build and lint the frontend

From the `frontend` directory:

```bash
npm run build
npm run lint
```

A successful build creates the production bundle in `frontend/dist/`. The project does not claim browser visual verification until you open the running dashboard and click through the pages locally.

## 10. Run the crypto benchmark analysis already included in the ZIP

The ZIP includes previously measured Phase 7 crypto benchmark results. It also includes a new reproducible Phase 16–17 analysis script.

From the project root, with the Python virtual environment activated:

```bash
python experiments/scripts/phase16_17_analysis.py
```

The command writes these files to `experiments/results/`:

```text
phase16_17_summary.json
policy_regret.csv
crypto_total_operation_seconds.png
crypto_throughput.png
crypto_overhead.png
```

The included results were measured on the earlier sandbox hardware. They are not new measurements from your computer. To run the full benchmark suite on your own hardware, review the existing benchmark module and run:

```bash
python -m crypto.benchmarks.run_suite
python -m crypto.benchmarks.threshold_analysis
```

Record your hardware, operating system, Python version, cryptography package version, repetitions, and output files before using those results in a report.

## 11. Run the optional Docker deployment

Docker Desktop must be installed and running.

From the project root, build and start the complete stack:

```bash
docker compose up --build
```

The services are intended to be available at:

- Frontend: <http://localhost:5173>
- Backend API: <http://localhost:8000>
- Backend docs: <http://localhost:8000/docs>
- MongoDB: `localhost:27017`

The compose file starts MongoDB first, waits for its health check, then starts the backend and frontend. It mounts local `ml/models` and `experiments/results` into the backend container as read-only directories.

To run in the background:

```bash
docker compose up --build -d
```

To view logs:

```bash
docker compose logs -f backend
docker compose logs -f frontend
docker compose logs -f mongodb
```

To stop the stack:

```bash
docker compose down
```

To stop it and delete the MongoDB volume as well, which removes stored database data:

```bash
docker compose down -v
```

Use the last command only when you intentionally want to delete the local database volume.

## 12. Add the CICIDS2017 dataset for real ML evaluation

## 12A. Optional: run the included synthetic fixture first

The ZIP now includes a small, deterministic **synthetic CICIDS2017-like fixture**. It has CICFlowMeter-style column names and common label strings so that you can verify the preprocessing and training commands before obtaining the official dataset.

This fixture is **not CICIDS2017**. Its model metrics are synthetic software-test outputs and must never be reported as real IDS accuracy, dataset statistics, or research findings.

From the project root, with the Python virtual environment activated, run:

```bash
python ml/data/generate_synthetic_fixture.py --output-dir ml/data/synthetic_raw --rows-per-file 40
python -m ml.preprocessing.pipeline \
  --raw-dir ml/data/synthetic_raw \
  --processed-dir ml/data/synthetic_processed \
  --output-dir experiments/results/synthetic_fixture \
  --seed 42
python -m ml.training.run_random_forest \
  --processed-dir ml/data/synthetic_processed \
  --output-dir experiments/results/synthetic_fixture \
  --model-dir ml/models/synthetic_fixture \
  --seed 42 --n-estimators 50
python -m ml.training.run_xgboost \
  --processed-dir ml/data/synthetic_processed \
  --output-dir experiments/results/synthetic_fixture \
  --model-dir ml/models/synthetic_fixture \
  --seed 42 --n-estimators 50
```

All outputs are deliberately stored under `synthetic_fixture/` and `ml/models/synthetic_fixture/` so they are not confused with real-data outputs. The generator is deterministic when the same seed is used. Delete those directories and rerun the commands to start over.

The successful sandbox validation produced synthetic-only validation metrics. Those numbers verify that the code path runs; they do not estimate performance on CICIDS2017.

## 12B. Add the CICIDS2017 dataset for real ML evaluation

The final ZIP does not include the dataset. Obtain it from the official Canadian Institute for Cybersecurity source and follow its usage terms. Place the CSV files in:

```text
ml/data/raw/
```

Then inspect the documented preprocessing configuration before running it:

```bash
python -m ml.preprocessing.pipeline --help
```

Run preprocessing using the command shown by the module help and project documentation. Then train the models:

```bash
python -m ml.training.run_random_forest --help
python -m ml.training.run_xgboost --help
```

Use the actual command-line arguments appropriate to your local files. Do not invent accuracy or class-distribution numbers. Preserve the generated JSON and report files under `experiments/results/` or another clearly named output directory.

The correct research workflow is:

1. Record the source files and their checksums.
2. Run preprocessing.
3. Inspect the preprocessing report and leakage checks.
4. Train Random Forest.
5. Train XGBoost.
6. Compare accuracy, precision, recall, F1, ROC-AUC, confusion matrices, runtime, and memory.
7. Update the research report only with the actual generated values.

## 13. Test the main application flow

With the backend running, open Swagger at <http://127.0.0.1:8000/docs>.

Recommended order:

1. Call `/health`.
2. Review `/benchmarks` to confirm the measured benchmark results are visible.
3. Review the event endpoints and confirm whether storage is MongoDB or the in-memory fallback.
4. Test the crypto endpoints using the configured bearer token.
5. Test detection only after a trained model is available. Without a trained model, the API correctly returns an unavailable-service response rather than fabricating a prediction.
6. Confirm that malicious detections create WebSocket alerts.
7. Confirm that high or critical detections with a source IP create a simulated firewall action.
8. Open the dashboard and verify its Overview, Live Attacks, Detection Analytics, Crypto Analytics, SAHE Decisions, Benchmark Results, and Firewall Actions pages.

## 14. Common problems and fixes

### `python` or `python3` is not recognized

Install Python, restart VS Code, and select the `.venv` interpreter using **Python: Select Interpreter**.

### `pip install` fails while installing XGBoost or scientific packages

Use Python 3.11 or 3.12, upgrade pip, and retry inside a fresh `.venv`. On Windows, install the current Microsoft C++ runtime if a compiled dependency requests it.

### `ModuleNotFoundError: backend`

Run commands from the project root, not from inside `backend/`. Use:

```bash
python -m uvicorn backend.app.main:app --reload
```

### Dashboard shows a network error

Verify the backend is running, check port 8000, confirm CORS settings, and reload the page after `npm run dev` starts successfully.

### MongoDB connection errors

Start MongoDB locally or run Docker Desktop. If MongoDB is intentionally unavailable, use the documented fallback and confirm that responses identify the fallback storage backend.

### Port 8000 or 5173 is already in use

Stop the conflicting process or run the backend on another port and update the frontend API base configuration accordingly.

### Detection returns 503 or no model is available

This is expected until a real CICIDS2017-trained model exists in `ml/models/`. Do not create a fake model or report fake detection metrics.

### Docker build fails

Confirm Docker Desktop is running, run `docker compose config`, check that the project root is the current directory, and rebuild with:

```bash
docker compose build --no-cache
```

## 15. Recommended first-day checklist

- [ ] Extract the ZIP and open the `sahe-cloud-ids` folder in VS Code.
- [ ] Create and activate `.venv`.
- [ ] Install `backend/requirements.txt`.
- [ ] Copy `.env.example` to `.env` and set a local API token.
- [ ] Run the backend and open `/health` and `/docs`.
- [ ] Install frontend packages and run the dashboard.
- [ ] Run `python -m pytest -q`.
- [ ] Run `npm run build` and `npm run lint`.
- [ ] Run `python experiments/scripts/phase16_17_analysis.py`.
- [ ] Install Docker Desktop and run `docker compose up --build` if container verification is required.
- [ ] Obtain CICIDS2017 separately before making real ML claims.

## 16. Evidence boundary

The project deliberately distinguishes three states:

- **Verified:** executed in the current or earlier documented environment, such as cryptographic round trips and software tests.
- **Synthetic validation:** executed with generated fixtures to test code behavior, not a real-world result.
- **NOT EXECUTED YET:** requires the user's dataset, hardware, browser, MongoDB server, or Docker runtime.

Keep these labels when presenting or extending the project. They are essential to the credibility of the final-year research work.
