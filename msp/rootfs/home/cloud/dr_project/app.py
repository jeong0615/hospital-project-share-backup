import os
from pathlib import Path

from chatops_core import create_app


REPO_ROOT = Path(__file__).resolve().parents[2]


app = create_app(
    default_state_db=os.environ.get("CHATOPS_STATE_DB", "/var/lib/hospital-dr/chatops_state.sqlite3"),
    default_secret_file="/home/cloud/hospital-dr-secrets/dr.env",
    default_script_root=os.environ.get(
        "DR_SCRIPT_ROOT", str(REPO_ROOT / "infra" / "terraform")
    ),
)
