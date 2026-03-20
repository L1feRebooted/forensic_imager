# ForensicImager — College Project

A Python/Flask forensic imaging dashboard inspired by FTK Imager and Logicube Falcon Neo.

---

## Folder Structure

```
forensic_imager/
│
├── app.py                  ← Flask app + WMI/pywin32 backend
├── requirements.txt        ← Python dependencies
├── README.md
│
├── templates/
│   └── index.html          ← Main dashboard UI (Jinja2 / plain HTML)
│
├── static/                 ← (create as needed)
│   ├── css/
│   ├── js/
│   └── img/
│
├── engine/                 ← (next sprint) acquisition engine modules
│   ├── __init__.py
│   ├── imager.py           ← Raw sector-by-sector read logic
│   ├── hasher.py           ← MD5 / SHA-256 hash verification
│   └── report.py           ← Case report generator
│
└── output/                 ← Forensic image output directory
    └── .gitkeep
```

---

## Setup

### 1. Install dependencies
```bash
pip install -r requirements.txt
```

### 2. Run as Administrator
Raw physical drive access requires elevated privileges on Windows.
Right-click your terminal → "Run as Administrator", then:

```bash
python app.py
```

### 3. Open the dashboard
Navigate to: http://127.0.0.1:5000

---

## API Endpoints

| Method | Route                            | Description                             |
|--------|----------------------------------|-----------------------------------------|
| GET    | `/`                              | Dashboard HTML                          |
| GET    | `/api/drives`                    | List all physical drives (WMI)          |
| GET    | `/api/drives/<index>`            | Full detail for one drive               |
| GET    | `/api/drives/<index>/geometry`   | Raw IOCTL disk geometry                 |

---

## Next Steps (Sprint 2)

- [ ] `engine/imager.py` — sector-by-sector DD-style acquisition
- [ ] `engine/hasher.py` — MD5/SHA-256 hash with progress streaming
- [ ] `/api/drives/<index>/acquire` — POST to start an imaging job
- [ ] Server-Sent Events (SSE) for real-time acquisition progress bar
- [ ] Case metadata form (examiner name, case number, evidence label)
- [ ] E01/AFF format output support

---

## ⚠ Forensic Notes

- Always image to a **write-blocked** or known-clean destination.
- Hash the source drive **before** and **after** acquisition to prove integrity.
- This tool operates in **read-only** mode by default — no write calls are made to source drives.
