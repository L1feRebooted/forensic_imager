"""
ForensicImager - Flask + SocketIO Backend
Physical drive acquisition engine with real-time progress streaming.
Requires Administrator privileges on Windows.
"""

from flask import Flask, jsonify, render_template, abort, request
from flask_socketio import SocketIO, emit
import wmi
import win32file
import win32con
import struct
import hashlib
import threading
import time
import os

# ── App Setup ─────────────────────────────────────────────────────────────────

app = Flask(__name__)
app.config["SECRET_KEY"] = "forensic-imager-secret"

# async_mode='threading' is required for background threads to emit events
socketio = SocketIO(app, async_mode="threading", cors_allowed_origins="*")

# Output directory for .dd images
OUTPUT_DIR = os.path.join(os.path.dirname(__file__), "output")
os.makedirs(OUTPUT_DIR, exist_ok=True)

# Track active jobs so we can cancel them { job_id -> {"cancel": bool} }
active_jobs: dict = {}

CHUNK_SIZE = 1024 * 1024  # 1 MB per read


# ── Drive Helpers ──────────────────────────────────────────────────────────────

def get_physical_drives():
    drives = []
    seen = set()
    try:
        # Primary query
        c = wmi.WMI()
        for disk in c.Win32_DiskDrive():
            seen.add(disk.Index)
            drives.append({
                "index":      disk.Index,
                "device_id":  disk.DeviceID,
                "model":      disk.Model or "Unknown",
                "serial":     (disk.SerialNumber or "N/A").strip(),
                "interface":  disk.InterfaceType or "Unknown",
                "media_type": disk.MediaType or "Unknown",
                "size_bytes": int(disk.Size) if disk.Size else 0,
                "size_gb":    round(int(disk.Size) / (1024 ** 3), 2) if disk.Size else 0,
                "partitions": disk.Partitions or 0,
                "status":     disk.Status or "Unknown",
                "firmware":   disk.FirmwareRevision or "N/A",
            })
    except Exception as e:
        app.logger.error(f"WMI Win32_DiskDrive failed: {e}")

    # Fallback — brute force scan PhysicalDrive0 to PhysicalDrive9
    # Catches USB drives that WMI sometimes misses
    for i in range(10):
        if i in seen:
            continue
        device_id = f"\\\\.\\PhysicalDrive{i}"
        try:
            handle = win32file.CreateFile(
                device_id,
                win32con.GENERIC_READ,
                win32con.FILE_SHARE_READ | win32con.FILE_SHARE_WRITE,
                None,
                win32con.OPEN_EXISTING,
                0,
                None
            )
            # If we can open it, the drive exists — read its size
            IOCTL_DISK_GET_LENGTH_INFO = 0x7405C
            try:
                buf = win32file.DeviceIoControl(handle, IOCTL_DISK_GET_LENGTH_INFO, None, 8)
                size_bytes = struct.unpack("Q", buf)[0]
            except:
                size_bytes = 0
            win32file.CloseHandle(handle)

            drives.append({
                "index":      i,
                "device_id":  device_id,
                "model":      f"PhysicalDrive{i} (USB/Unknown)",
                "serial":     "N/A",
                "interface":  "USB",
                "media_type": "External",
                "size_bytes": size_bytes,
                "size_gb":    round(size_bytes / (1024 ** 3), 2) if size_bytes else 0,
                "partitions": 0,
                "status":     "Unknown",
                "firmware":   "N/A",
            })
        except:
            pass  # Drive index doesn't exist, skip

    drives.sort(key=lambda d: d["index"])
    return drives


# ── Core Imaging Engine ────────────────────────────────────────────────────────

def forensic_imager(job_id: str, device_id: str, drive_index: int,
                    total_size: int, output_path: str, sid: str):
    """
    Reads a physical drive sector-by-sector in 1MB chunks,
    calculates MD5 on-the-fly, writes a .dd image, and streams
    progress + speed back to the frontend via SocketIO.

    Parameters
    ----------
    job_id      : Unique ID for this acquisition job.
    device_id   : e.g. '\\\\.\\PhysicalDrive1'
    drive_index : Integer index of the drive.
    total_size  : Total bytes to read (from WMI).
    output_path : Full path to the output .dd file.
    sid         : SocketIO session ID of the requesting client.
    """

    def emit_progress(event: str, data: dict):
        """Thread-safe SocketIO emit targeted to the specific client session."""
        socketio.emit(event, data, to=sid)

    # ── Open source drive (read-only) ──────────────────────────────────────
    try:
        handle = win32file.CreateFile(
            device_id,
            win32con.GENERIC_READ,
            win32con.FILE_SHARE_READ | win32con.FILE_SHARE_WRITE,
            None,
            win32con.OPEN_EXISTING,
            win32con.FILE_FLAG_SEQUENTIAL_SCAN,   # hint OS to prefetch
            None
        )
    except Exception as e:
        emit_progress("job_error", {
            "job_id":  job_id,
            "message": f"Failed to open drive: {e}",
            "hint":    "Make sure Flask is running as Administrator."
        })
        active_jobs.pop(job_id, None)
        return

    # ── Open destination .dd file ──────────────────────────────────────────
    try:
        out_file = open(output_path, "wb")
    except Exception as e:
        win32file.CloseHandle(handle)
        emit_progress("job_error", {"job_id": job_id, "message": f"Cannot create output file: {e}"})
        active_jobs.pop(job_id, None)
        return

    # ── Acquisition loop ───────────────────────────────────────────────────
    md5        = hashlib.md5()
    bytes_read = 0
    errors     = 0
    start_time = time.time()
    last_emit  = start_time

    emit_progress("job_started", {
        "job_id":      job_id,
        "device_id":   device_id,
        "output_path": output_path,
        "total_bytes": total_size,
    })

    try:
        while True:

            # ── Check for cancel signal ────────────────────────────────────
            if active_jobs.get(job_id, {}).get("cancel"):
                emit_progress("job_cancelled", {
                    "job_id":     job_id,
                    "bytes_read": bytes_read,
                })
                break

            # ── Read 1 MB chunk from physical drive ────────────────────────
            try:
                _hr, chunk = win32file.ReadFile(handle, CHUNK_SIZE)
            except Exception:
                errors += 1
                if errors > 50:
                    emit_progress("job_error", {
                        "job_id":  job_id,
                        "message": f"Aborted: too many consecutive read errors ({errors}).",
                    })
                    break
                # Bad block — fill with zeros to preserve image alignment
                chunk = b'\x00' * CHUNK_SIZE

            if not chunk:
                break  # Reached end of drive

            # ── Write to image file ────────────────────────────────────────
            out_file.write(chunk)

            # ── Update running MD5 ─────────────────────────────────────────
            md5.update(chunk)
            bytes_read += len(chunk)

            # ── Emit progress at most every 500 ms ────────────────────────
            now = time.time()
            if now - last_emit >= 0.5:
                elapsed      = now - start_time
                speed_mbs    = (bytes_read / (1024 * 1024)) / elapsed if elapsed > 0 else 0
                progress_pct = (bytes_read / total_size * 100) if total_size > 0 else 0
                eta_sec      = ((total_size - bytes_read) / (bytes_read / elapsed)) \
                                if bytes_read > 0 and elapsed > 0 else 0

                emit_progress("job_progress", {
                    "job_id":       job_id,
                    "bytes_read":   bytes_read,
                    "total_bytes":  total_size,
                    "progress_pct": round(progress_pct, 2),
                    "speed_mbs":    round(speed_mbs, 2),
                    "elapsed_sec":  round(elapsed, 1),
                    "eta_sec":      round(eta_sec, 0),
                    "errors":       errors,
                })
                last_emit = now

            # ── Stop when all bytes read ───────────────────────────────────
            if total_size > 0 and bytes_read >= total_size:
                break

    finally:
        out_file.close()
        win32file.CloseHandle(handle)

    # ── Job finished — write sidecar .md5 file ─────────────────────────────
    final_md5 = md5.hexdigest()
    elapsed   = time.time() - start_time
    avg_speed = (bytes_read / (1024 * 1024)) / elapsed if elapsed > 0 else 0

    md5_path = output_path + ".md5"
    try:
        with open(md5_path, "w") as f:
            f.write(f"File:      {os.path.basename(output_path)}\n")
            f.write(f"Source:    {device_id}\n")
            f.write(f"MD5:       {final_md5}\n")
            f.write(f"Bytes:     {bytes_read}\n")
            f.write(f"Errors:    {errors}\n")
            f.write(f"Avg Speed: {avg_speed:.2f} MB/s\n")
            f.write(f"Date:      {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
    except Exception as e:
        app.logger.warning(f"Could not write .md5 sidecar: {e}")

    emit_progress("job_complete", {
        "job_id":      job_id,
        "bytes_read":  bytes_read,
        "md5":         final_md5,
        "output_path": output_path,
        "md5_path":    md5_path,
        "elapsed_sec": round(elapsed, 1),
        "avg_speed":   round(avg_speed, 2),
        "errors":      errors,
    })

    active_jobs.pop(job_id, None)
def get_drive_geometry(device_id: str) -> dict:
    IOCTL_DISK_GET_DRIVE_GEOMETRY = 0x70000
    try:
        handle = win32file.CreateFile(
            device_id,
            win32con.GENERIC_READ,
            win32con.FILE_SHARE_READ | win32con.FILE_SHARE_WRITE,
            None, win32con.OPEN_EXISTING, 0, None
        )
        buf = win32file.DeviceIoControl(handle, IOCTL_DISK_GET_DRIVE_GEOMETRY, None, 24)
        win32file.CloseHandle(handle)
        if len(buf) < 24:
            return {"error": "Buffer too small"}
        cylinders, media_type, tracks, sectors, bytes_per_sector = struct.unpack("qIIII", buf[:24])
        return {
            "cylinders": cylinders,
            "tracks_per_cylinder": tracks,
            "sectors_per_track": sectors,
            "bytes_per_sector": bytes_per_sector,
        }
    except Exception as e:
        return {"error": str(e)}

# ── REST Routes ────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/drives", methods=["GET"])
def api_drives():
    drives = get_physical_drives()
    return jsonify({"success": True, "count": len(drives), "drives": drives})


@app.route("/api/drives/<int:drive_index>/geometry", methods=["GET"])
def api_drive_geometry(drive_index: int):
    device_id = f"\\\\.\\PhysicalDrive{drive_index}"
    return jsonify({"success": True, "device_id": device_id,
                    "geometry": get_drive_geometry(device_id)})


@app.route("/api/drives/<int:drive_index>", methods=["GET"])
def api_drive_detail(drive_index: int):
    drives = get_physical_drives()
    target = next((d for d in drives if d["index"] == drive_index), None)
    if not target:
        abort(404, description=f"PhysicalDrive{drive_index} not found")
    target["geometry"] = get_drive_geometry(target["device_id"])
    return jsonify({"success": True, "drive": target})


@app.route("/api/jobs", methods=["GET"])
def api_jobs():
    return jsonify({"success": True, "jobs": list(active_jobs.keys())})


@app.route("/api/jobs/<job_id>/cancel", methods=["POST"])
def api_cancel_job(job_id: str):
    if job_id in active_jobs:
        active_jobs[job_id]["cancel"] = True
        return jsonify({"success": True, "message": f"Cancel signal sent to {job_id}"})
    return jsonify({"success": False, "message": "Job not found"}), 404


# ── SocketIO Events ────────────────────────────────────────────────────────────

@socketio.on("connect")
def on_connect():
    print(f"[WS] Client connected: {request.sid}")
    emit("connected", {"message": "ForensicImager backend ready."})


@socketio.on("disconnect")
def on_disconnect():
    print(f"[WS] Client disconnected: {request.sid}")


@socketio.on("start_acquisition")
def on_start_acquisition(data):
    """
    Client sends:
    {
        "drive_index": 1,
        "output_filename": "evidence_001"   <- optional
    }
    """
    drive_index = data.get("drive_index")
    if drive_index is None:
        emit("job_error", {"message": "drive_index is required"})
        return

    drives = get_physical_drives()
    drive  = next((d for d in drives if d["index"] == drive_index), None)
    if not drive:
        emit("job_error", {"message": f"PhysicalDrive{drive_index} not found"})
        return

    timestamp   = time.strftime("%Y%m%d_%H%M%S")
    filename    = data.get("output_filename") or f"PhysicalDrive{drive_index}_{timestamp}"
    if not filename.endswith(".dd"):
        filename += ".dd"
    output_path = os.path.join(OUTPUT_DIR, filename)

    job_id = f"job_{drive_index}_{timestamp}"
    active_jobs[job_id] = {"cancel": False}
    sid = request.sid

    thread = threading.Thread(
        target=forensic_imager,
        args=(job_id, drive["device_id"], drive_index,
              drive["size_bytes"], output_path, sid),
        daemon=True
    )
    thread.start()

    emit("job_queued", {
        "job_id":      job_id,
        "device_id":   drive["device_id"],
        "output_path": output_path,
        "total_bytes": drive["size_bytes"],
    })


# ── Entry Point ────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("=" * 55)
    print("  ForensicImager — http://127.0.0.1:5000")
    print("  ⚠  Run as Administrator for raw drive access")
    print("=" * 55)
    socketio.run(app, host="127.0.0.1", port=5000, debug=False)
