import asyncio
import json
import os
from datetime import datetime, timezone

# ======================
# CONFIG
# ======================
HOST = "0.0.0.0"
PORT = 2525

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_DIR = os.path.abspath(os.path.join(BASE_DIR, "../../logs"))
LOG_FILE = os.path.join(LOG_DIR, "smtp_logs.jsonl")

os.makedirs(LOG_DIR, exist_ok=True)
open(LOG_FILE, "a").close()

# ======================
# LOGGING
# ======================
def log_event(data):
    with open(LOG_FILE, "a") as f:
        f.write(json.dumps(data) + "\n")

async def send_response(writer, source_ip, mail_from, rcpt_to, code, message, event, level="INFO"):
    response = f"{code} {message}\r\n"
    writer.write(response.encode())
    await writer.drain()

    log_event({
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "source_ip": source_ip,
        "honeypot_type": "smtp",
        "event": event,
        "data": {
            "mail_from": mail_from,
            "rcpt_to": rcpt_to,
            "smtp_response": f"{code} {message}"
        },
        "level": level
    })

# ======================
# SMTP CLIENT HANDLER
# ======================
async def handle_smtp_client(reader, writer):
    peer = writer.get_extra_info("peername")
    source_ip = peer[0] if peer else "unknown"

    mail_from = None
    rcpt_to = []
    email_data = []

    writer.write(b"220 phantomnet SMTP Service Ready\r\n")
    await writer.drain()

    log_event({
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "source_ip": source_ip,
        "honeypot_type": "smtp",
        "event": "connection_opened",
        "level": "INFO"
    })

    try:
        while True:
            data = await reader.readline()
            if not data:
                break

            command = data.decode(errors="ignore").rstrip("\r\n")
            upper_cmd = command.upper()

            # HELO
            if upper_cmd.startswith("HELO"):
                hostname = command[5:].strip()

                log_event({
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "source_ip": source_ip,
                    "honeypot_type": "smtp",
                    "event": "helo",
                    "data": {"hostname": hostname},
                    "level": "INFO"
                })

                await send_response(writer, source_ip, mail_from, rcpt_to, 250, "Hello", "helo_response")

            # EHLO
            elif upper_cmd.startswith("EHLO"):
                hostname = command[5:].strip()

                log_event({
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "source_ip": source_ip,
                    "honeypot_type": "smtp",
                    "event": "ehlo",
                    "data": {"hostname": hostname},
                    "level": "INFO"
                })

                writer.write(
                    b"250-phantomnet SMTP Service\r\n"
                    b"250 SIZE 35882577\r\n"
                )
                await writer.drain()

            # MAIL FROM
            elif upper_cmd.startswith("MAIL FROM:"):
                mail_from = command[10:].strip("<> ")

                await send_response(
                    writer, source_ip, mail_from, rcpt_to,
                    250, "OK", "mail_from", "WARN"
                )

            # RCPT TO
            elif upper_cmd.startswith("RCPT TO:"):
                recipient = command[8:].strip("<> ")
                rcpt_to.append(recipient)

                await send_response(
                    writer, source_ip, mail_from, rcpt_to,
                    250, "OK", "rcpt_to", "WARN"
                )

            # DATA
            elif upper_cmd == "DATA":
                writer.write(b"354 End data with <CR><LF>.<CR><LF>\r\n")
                await writer.drain()

                email_data.clear()

                while True:
                    line = await reader.readline()
                    if not line:
                        break

                    text = line.decode(errors="ignore").rstrip("\r\n")
                    if text == ".":
                        break
                    email_data.append(text)

                full_message = "\n".join(email_data)

                log_event({
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "source_ip": source_ip,
                    "honeypot_type": "smtp",
                    "event": "data",
                    "data": {
                        "mail_from": mail_from,
                        "rcpt_to": rcpt_to,
                        "message": full_message
                    },
                    "level": "ERROR"
                })

                await send_response(
                    writer, source_ip, mail_from, rcpt_to,
                    250, "Message accepted for delivery", "data_response", "ERROR"
                )

            # NOOP
            elif upper_cmd == "NOOP":
                await send_response(writer, source_ip, mail_from, rcpt_to, 250, "OK", "noop")

            # RSET
            elif upper_cmd == "RSET":
                mail_from = None
                rcpt_to.clear()
                email_data.clear()

                await send_response(writer, source_ip, mail_from, rcpt_to, 250, "OK", "rset")

            # QUIT
            elif upper_cmd == "QUIT":
                await send_response(writer, source_ip, mail_from, rcpt_to, 221, "Bye", "quit")
                break

            # DEFAULT
            else:
                await send_response(writer, source_ip, mail_from, rcpt_to, 250, "OK", "unknown")

    except Exception as e:
        log_event({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "source_ip": source_ip,
            "honeypot_type": "smtp",
            "event": "error",
            "data": {"error": str(e)},
            "level": "ERROR"
        })

    finally:
        writer.close()
        await writer.wait_closed()

        log_event({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "source_ip": source_ip,
            "honeypot_type": "smtp",
            "event": "connection_closed",
            "level": "INFO"
        })

# ======================
# SERVER START
# ======================
async def start_server():
    server = await asyncio.start_server(handle_smtp_client, HOST, PORT)
    print(f"[+] SMTP Honeypot listening on port {PORT}")
    async with server:
        await server.serve_forever()

if __name__ == "__main__":
    asyncio.run(start_server())
