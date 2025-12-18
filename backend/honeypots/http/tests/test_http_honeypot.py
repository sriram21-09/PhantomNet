import subprocess
import time
import requests

BASE_URL = "http://localhost:8080"

def test_get_admin():
    r = requests.get(f"{BASE_URL}/admin")
    assert r.status_code == 200
    assert "Admin Panel" in r.text


def test_post_admin():
    r = requests.post(
        f"{BASE_URL}/admin",
        data={"username": "admin", "password": "1234"}
    )
    assert r.status_code == 403
    assert "Invalid credentials" in r.text


def test_put_admin():
    r = requests.put(f"{BASE_URL}/admin")
    assert r.status_code in [403, 404]


def test_delete_admin():
    r = requests.delete(f"{BASE_URL}/admin")
    assert r.status_code in [403, 404]
