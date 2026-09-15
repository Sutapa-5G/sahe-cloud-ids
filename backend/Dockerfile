FROM python:3.12-slim

WORKDIR /app

# System deps for building some Python packages (e.g. cryptography's
# native extension) if a wheel isn't available for the target platform.
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

COPY backend/requirements.txt ./backend/requirements.txt
RUN pip install --no-cache-dir -r backend/requirements.txt

# Copy the whole repo (backend depends on ml/, crypto/ as sibling
# packages — see the import paths in backend/app/*.py).
COPY . .

EXPOSE 8000

CMD ["uvicorn", "backend.app.main:app", "--host", "0.0.0.0", "--port", "8000"]
