Write-Host "Starting CyberShield Intrusion Detection Platform..." -ForegroundColor Cyan
python -m uvicorn backend.main:app --host 127.0.0.1 --port 8000 --reload
