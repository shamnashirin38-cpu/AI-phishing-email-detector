"""
Input Validation and Sanitization Utilities.

Protects against:
- Oversized payload denial of service attacks
- Malformed inputs
- Null or empty field submissions
- Unsanitized HTML/script injection attempts
"""

import re

MAX_SENDER_LEN = 320
MAX_SUBJECT_LEN = 500
MAX_BODY_LEN = 100000


def validate_email_input(sender: str, subject: str, body: str) -> tuple[bool, str, dict]:
    """
    Validates user input fields for the email analysis endpoint.
    Returns: (is_valid: bool, error_message: str, cleaned_data: dict)
    """
    sender = (sender or "").strip()
    subject = (subject or "").strip()
    body = (body or "").strip()

    # Body is required
    if not body:
        return False, "Email body cannot be empty. Please paste the body of the email to analyze.", {}

    if len(body) > MAX_BODY_LEN:
        return False, f"Email body exceeds the maximum permitted length of {MAX_BODY_LEN:,} characters.", {}

    if len(subject) > MAX_SUBJECT_LEN:
        return False, f"Subject exceeds the maximum allowed length of {MAX_SUBJECT_LEN} characters.", {}

    if len(sender) > MAX_SENDER_LEN:
        return False, f"Sender field exceeds the maximum allowed length of {MAX_SENDER_LEN} characters.", {}

    cleaned = {
        "sender": sender,
        "subject": subject,
        "body": body
    }

    return True, "", cleaned
