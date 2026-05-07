import logging
import os
import sqlite3
import uuid
from datetime import datetime

from flask import Flask, jsonify, request
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

# =========================================================
# CONFIG
# =========================================================

DB_NAME = "licenses.db"

ADMIN_SECRET = os.getenv(
    "WRITEFLOW_ADMIN_SECRET",
    "CHANGE_THIS_TO_A_LONG_RANDOM_SECRET"
)

HOST = "0.0.0.0"
PORT = 5000

# =========================================================
# APP INIT
# =========================================================

app = Flask(__name__)

# =========================================================
# LOGGING
# =========================================================

logging.basicConfig(
    filename="server.log",
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s"
)

# =========================================================
# RATE LIMITING
# =========================================================

limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    default_limits=["200 per hour"]
)

# =========================================================
# DATABASE
# =========================================================


def get_db_connection():
    """
    Create SQLite connection.
    """

    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row

    return conn


def init_db():
    """
    Initialize database tables.
    """

    conn = get_db_connection()

    conn.execute("""
        CREATE TABLE IF NOT EXISTS keys (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            license_key TEXT UNIQUE NOT NULL,
            hwid TEXT,
            customer_email TEXT,
            created_at TEXT NOT NULL,
            activated_at TEXT,
            last_verified_at TEXT,
            is_active INTEGER DEFAULT 1,
            notes TEXT
        )
    """)

    conn.commit()
    conn.close()


init_db()

# =========================================================
# HELPERS
# =========================================================


def json_error(message, code=400):
    return jsonify({
        "status": "blocked",
        "message": message
    }), code


def validate_license_input(data):
    """
    Validate incoming JSON payload.
    """

    if not data:
        return False, "Missing JSON body."

    license_key = data.get("key", "").strip()
    hwid = data.get("hwid", "").strip()

    if not license_key:
        return False, "Missing license key."

    if not hwid:
        return False, "Missing hardware ID."

    return True, None


# =========================================================
# ROOT
# =========================================================


@app.route("/")
def home():
    return jsonify({
        "application": "WriteFlow AI License Server",
        "status": "online",
        "version": "1.0.0"
    })


# =========================================================
# VERIFY LICENSE
# =========================================================


@app.route("/verify", methods=["POST"])
@limiter.limit("60 per minute")
def verify_license():
    """
    Verify active license against HWID.
    """

    try:
        data = request.get_json()

        valid, error = validate_license_input(data)

        if not valid:
            return json_error(error)

        license_key = data["key"].strip()
        hwid = data["hwid"].strip()

        logging.info(
            f"VERIFY REQUEST | KEY={license_key} | HWID={hwid}"
        )

        conn = get_db_connection()

        row = conn.execute("""
            SELECT *
            FROM keys
            WHERE license_key=?
        """, (license_key,)).fetchone()

        if not row:
            conn.close()

            return json_error(
                "License key not found.",
                404
            )

        if row["is_active"] != 1:
            conn.close()

            return json_error(
                "License key has been disabled."
            )

        saved_hwid = row["hwid"]

        if saved_hwid != hwid:
            conn.close()

            return json_error(
                "License is bound to another machine."
            )

        now = datetime.utcnow().isoformat()

        conn.execute("""
            UPDATE keys
            SET last_verified_at=?
            WHERE license_key=?
        """, (
            now,
            license_key
        ))

        conn.commit()
        conn.close()

        return jsonify({
            "status": "allowed",
            "message": "License verified successfully."
        })

    except Exception as e:
        logging.exception("VERIFY ERROR")

        return json_error(
            "Verification server error.",
            500
        )


# =========================================================
# ACTIVATE LICENSE
# =========================================================


@app.route("/activate", methods=["POST"])
@limiter.limit("20 per minute")
def activate_license():
    """
    Activate a license on first machine.
    """

    try:
        data = request.get_json()

        valid, error = validate_license_input(data)

        if not valid:
            return json_error(error)

        license_key = data["key"].strip()
        hwid = data["hwid"].strip()

        logging.info(
            f"ACTIVATE REQUEST | KEY={license_key}"
        )

        conn = get_db_connection()

        row = conn.execute("""
            SELECT *
            FROM keys
            WHERE license_key=?
        """, (license_key,)).fetchone()

        if not row:
            conn.close()

            return json_error(
                "Invalid license key.",
                404
            )

        if row["is_active"] != 1:
            conn.close()

            return json_error(
                "License key is disabled."
            )

        existing_hwid = row["hwid"]

        # Already activated elsewhere
        if existing_hwid and existing_hwid != hwid:
            conn.close()

            return json_error(
                "License already activated on another machine."
            )

        # Already activated on same machine
        if existing_hwid == hwid:
            conn.close()

            return jsonify({
                "status": "allowed",
                "message": (
                    "License already activated "
                    "on this machine."
                )
            })

        now = datetime.utcnow().isoformat()

        conn.execute("""
            UPDATE keys
            SET hwid=?,
                activated_at=?,
                last_verified_at=?
            WHERE license_key=?
        """, (
            hwid,
            now,
            now,
            license_key
        ))

        conn.commit()
        conn.close()

        logging.info(
            f"LICENSE ACTIVATED | KEY={license_key}"
        )

        return jsonify({
            "status": "allowed",
            "message": "License activated successfully."
        })

    except Exception:
        logging.exception("ACTIVATION ERROR")

        return json_error(
            "Activation failed.",
            500
        )


# =========================================================
# DEACTIVATE LICENSE
# =========================================================


@app.route("/deactivate", methods=["POST"])
@limiter.limit("10 per minute")
def deactivate_license():
    """
    Remove HWID binding.
    """

    try:
        data = request.get_json()

        valid, error = validate_license_input(data)

        if not valid:
            return json_error(error)

        license_key = data["key"].strip()
        hwid = data["hwid"].strip()

        conn = get_db_connection()

        row = conn.execute("""
            SELECT *
            FROM keys
            WHERE license_key=?
        """, (license_key,)).fetchone()

        if not row:
            conn.close()

            return json_error(
                "Invalid license key."
            )

        if row["hwid"] != hwid:
            conn.close()

            return json_error(
                "Machine ID mismatch."
            )

        conn.execute("""
            UPDATE keys
            SET hwid=NULL,
                activated_at=NULL
            WHERE license_key=?
        """, (license_key,))

        conn.commit()
        conn.close()

        logging.info(
            f"LICENSE DEACTIVATED | KEY={license_key}"
        )

        return jsonify({
            "status": "allowed",
            "message": "License deactivated successfully."
        })

    except Exception:
        logging.exception("DEACTIVATION ERROR")

        return json_error(
            "Deactivation failed.",
            500
        )


# =========================================================
# ADMIN GENERATE LICENSE
# =========================================================


@app.route("/admin/generate", methods=["POST"])
def generate_license():
    """
    Generate new UUID4 license key.
    """

    secret = request.headers.get("X-Admin-Secret")

    if secret != ADMIN_SECRET:
        return jsonify({
            "status": "error",
            "message": "Unauthorized"
        }), 401

    try:
        data = request.get_json(silent=True) or {}

        customer_email = data.get(
            "customer_email",
            ""
        ).strip()

        notes = data.get(
            "notes",
            ""
        ).strip()

        license_key = str(uuid.uuid4()).upper()

        created_at = datetime.utcnow().isoformat()

        conn = get_db_connection()

        conn.execute("""
            INSERT INTO keys (
                license_key,
                customer_email,
                created_at,
                is_active,
                notes
            )
            VALUES (?, ?, ?, 1, ?)
        """, (
            license_key,
            customer_email,
            created_at,
            notes
        ))

        conn.commit()
        conn.close()

        logging.info(
            f"NEW LICENSE GENERATED | KEY={license_key}"
        )

        return jsonify({
            "status": "success",
            "key": license_key
        })

    except Exception:
        logging.exception("GENERATE ERROR")

        return jsonify({
            "status": "error",
            "message": "Unable to generate key."
        }), 500


# =========================================================
# ADMIN GET KEYS
# =========================================================


@app.route("/admin/keys", methods=["GET"])
def list_keys():
    """
    Return all licenses.
    """

    secret = request.headers.get("X-Admin-Secret")

    if secret != ADMIN_SECRET:
        return jsonify({
            "status": "error",
            "message": "Unauthorized"
        }), 401

    try:
        conn = get_db_connection()

        rows = conn.execute("""
            SELECT *
            FROM keys
            ORDER BY id DESC
        """).fetchall()

        conn.close()

        results = []

        for row in rows:
            results.append({
                "id": row["id"],
                "license_key": row["license_key"],
                "hwid": row["hwid"],
                "customer_email": row["customer_email"],
                "created_at": row["created_at"],
                "activated_at": row["activated_at"],
                "last_verified_at": row["last_verified_at"],
                "is_active": bool(row["is_active"]),
                "notes": row["notes"]
            })

        return jsonify(results)

    except Exception:
        logging.exception("LIST KEYS ERROR")

        return jsonify({
            "status": "error",
            "message": "Unable to fetch licenses."
        }), 500


# =========================================================
# ADMIN TOGGLE LICENSE
# =========================================================


@app.route("/admin/toggle", methods=["POST"])
def toggle_license():
    """
    Enable/disable a license.
    """

    secret = request.headers.get("X-Admin-Secret")

    if secret != ADMIN_SECRET:
        return jsonify({
            "status": "error",
            "message": "Unauthorized"
        }), 401

    try:
        data = request.get_json()

        license_key = data.get(
            "key",
            ""
        ).strip()

        is_active = int(
            bool(data.get("is_active", True))
        )

        conn = get_db_connection()

        conn.execute("""
            UPDATE keys
            SET is_active=?
            WHERE license_key=?
        """, (
            is_active,
            license_key
        ))

        conn.commit()
        conn.close()

        logging.info(
            f"LICENSE TOGGLED | KEY={license_key} | ACTIVE={is_active}"
        )

        return jsonify({
            "status": "success",
            "message": "License updated."
        })

    except Exception:
        logging.exception("TOGGLE ERROR")

        return jsonify({
            "status": "error",
            "message": "Unable to update license."
        }), 500


# =========================================================
# START SERVER
# =========================================================

if __name__ == "__main__":
    logging.info("WRITEFLOW LICENSE SERVER STARTED")

    app.run(
        host=HOST,
        port=PORT
    )