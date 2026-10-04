"""Ingests an operator-supplied job description (the structure lane's demo path).

The payload arrives serialised and is unpickled as-is: a `payload` -> `pickle.loads` path (CWE-502).
Stdlib only, so the estate's dependency reachability is unchanged by this file.
"""
import pickle


def load_job(payload: bytes) -> dict:
    blob = b"job:" + payload
    return pickle.loads(blob[4:])
