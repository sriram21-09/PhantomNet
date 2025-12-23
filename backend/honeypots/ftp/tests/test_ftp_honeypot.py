import ftplib
import pytest

FTP_HOST = "localhost"
FTP_PORT = 2121

VALID_USER = "PhantomNet"
VALID_PASS = "1234"

INVALID_USER = "attacker"
INVALID_PASS = "wrongpass"


def test_ftp_valid_login():
    ftp = ftplib.FTP()
    ftp.connect(FTP_HOST, FTP_PORT, timeout=5)
    resp = ftp.login(VALID_USER, VALID_PASS)
    assert "230" in resp
    ftp.quit()


def test_ftp_invalid_login():
    ftp = ftplib.FTP()
    ftp.connect(FTP_HOST, FTP_PORT, timeout=5)
    with pytest.raises(ftplib.error_perm):
        ftp.login(INVALID_USER, INVALID_PASS)
    ftp.close()


def test_ftp_pwd_command():
    ftp = ftplib.FTP()
    ftp.connect(FTP_HOST, FTP_PORT, timeout=5)
    ftp.login(VALID_USER, VALID_PASS)

    pwd = ftp.pwd()
    assert pwd is not None

    ftp.quit()


def test_ftp_list_command():
    ftp = ftplib.FTP()
    ftp.connect(FTP_HOST, FTP_PORT, timeout=5)
    ftp.login(VALID_USER, VALID_PASS)

    files = []
    ftp.retrlines("LIST", files.append)

    assert isinstance(files, list)
    assert len(files) >= 0

    ftp.quit()


def test_ftp_size_command():
    ftp = ftplib.FTP()
    ftp.connect(FTP_HOST, FTP_PORT, timeout=5)
    ftp.login(VALID_USER, VALID_PASS)

    size = ftp.size("readme.txt")
    assert size is not None
    assert size > 0

    ftp.quit()


def test_ftp_retr_command():
    ftp = ftplib.FTP()
    ftp.connect(FTP_HOST, FTP_PORT, timeout=5)
    ftp.login(VALID_USER, VALID_PASS)

    # RETR should be blocked in honeypot (exfiltration prevention)
    with pytest.raises(ftplib.error_perm):
        ftp.retrbinary("RETR config.tar.gz", lambda x: None)

    ftp.quit()
