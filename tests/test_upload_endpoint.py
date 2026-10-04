import urllib.request
import json
from pathlib import Path

def test_upload():
    csv_bytes = Path("data/sample_security_logs.csv").read_bytes()
    boundary = "----TestBoundary12345"
    head = (f"--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"upload_test.csv\"\r\nContent-Type: text/csv\r\n\r\n").encode("utf-8")
    tail = f"\r\n--{boundary}--\r\n".encode("utf-8")
    body = head + csv_bytes + tail
    
    ports = [8000, 8080]
    res = None
    data = None
    for port in ports:
        try:
            req = urllib.request.Request(
                f"http://127.0.0.1:{port}/api/analyze/upload",
                data=body,
                headers={"Content-Type": f"multipart/form-data; boundary={boundary}"}
            )
            res = urllib.request.urlopen(req)
            data = json.loads(res.read().decode("utf-8"))
            break
        except Exception:
            continue

    if not data or not res:
        raise RuntimeError("FastAPI server not responding on port 8000 or 8080")
    print("UPLOAD STATUS:", res.status)
    print("PARSED EVENTS:", len(data["events"]))
    print("INCIDENTS IDENTIFIED:", len(data["incidents"]))
    assert res.status == 200
    assert len(data["events"]) == 76
    assert len(data["incidents"]) == 3
    print("CSV UPLOAD END-TO-END PASSED!")

if __name__ == "__main__":
    test_upload()
