#!/usr/bin/env python3

from aiosmtpd.controller import Controller
import asyncio
import datetime
import json

LOG_FILE = "/tmp/smtp_honeypot.log"

class SMTPHoneypotHandler:
    async def handle_DATA(self, server, session, envelope):
        log_entry = {
            "timestamp": datetime.datetime.utcnow().isoformat(),
            "source_ip": session.peer[0],
            "source_port": session.peer[1],
            "mail_from": envelope.mail_from,
            "rcpt_to": envelope.rcpt_tos,
            "data_preview": envelope.content[:200].decode(errors="ignore")
        }

        with open(LOG_FILE, "a") as f:
            f.write(json.dumps(log_entry) + "\n")

        print(f"[SMTP-HONEYPOT] Captured email from {session.peer[0]}")
        return "250 OK"

if __name__ == "__main__":
    handler = SMTPHoneypotHandler()
    controller = Controller(handler, hostname="0.0.0.0", port=25)
    controller.start()

    print("[*] SMTP Honeypot listening on 0.0.0.0:25")
    try:
        asyncio.get_event_loop().run_forever()
    except KeyboardInterrupt:
        controller.stop()
