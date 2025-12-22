import requests

BASE_URL = "http://localhost:8080"

def test_get_admin():
    """Admin page should load"""
    r = requests.get(f"{BASE_URL}/admin")
    assert r.status_code == 200
    assert "Admin Dashboard" in r.text


def test_post_admin():
    """Login attempt should fail but be accepted"""
    r = requests.post(
        f"{BASE_URL}/admin",
        data={"username": "admin", "password": "1234"}
    )
    assert r.status_code == 403
    assert "Invalid credentials" in r.text


def test_put_admin():
    """PUT should be forbidden"""
    r = requests.put(f"{BASE_URL}/admin")
    assert r.status_code == 403


def test_delete_admin():
    """DELETE should return not found"""
    r = requests.delete(f"{BASE_URL}/admin")
    assert r.status_code == 404
