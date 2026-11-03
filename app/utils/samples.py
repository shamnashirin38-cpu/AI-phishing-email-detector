"""
Predefined sample emails for testing, demonstration, and college viva presentations.
Includes:
- Obvious Credential Phishing (Banking suspension + IP link + password prompt)
- Multi-factor / OTP Interception Phishing
- Invoice & Cryptocurrency Fraud
- Ambiguous Delivery Notification
- Legitimate Academic / Business Communication
"""

SAMPLE_EMAILS = [
    {
        "id": "sample_banking_phish",
        "title": "🚨 Urgent Banking Suspension (Phishing)",
        "type": "phishing",
        "sender": "PayPal Support Team <security-alert@mailer-secure92.xyz>",
        "subject": "URGENT: Your Account Has Been Suspended - Action Required Within 24 Hours",
        "body": """Dear Customer,

We have detected unauthorized login attempts to your PayPal account from an unrecognized IP address. For your security, your account has been temporarily suspended.

You are required to verify your identity and enter your current password immediately. Failure to take action within 24 hours will result in permanent account termination and legal action.

Please click the secure link below to confirm your credentials:
http://192.168.1.105/paypal/secure-login.php

Thank you for your prompt cooperation,
PayPal Security Department"""
    },
    {
        "id": "sample_otp_harvesting",
        "title": "🔑 2FA / OTP Interception (Phishing)",
        "type": "phishing",
        "sender": "Microsoft Account Security <verify@micros0ft-support.com>",
        "subject": "Single-use verification code request",
        "body": """Hi user,

Someone requested a one-time password (OTP) to access your corporate Microsoft 365 account.

Your two-factor verification code is: 489201

If this was not you, someone knows your password! Please click here to reset your password and confirm your identity:
http://bit.ly/msoffice365-verify-pin

Do not ignore this critical alert."""
    },
    {
        "id": "sample_crypto_invoice",
        "title": "💰 Overdue Invoice & Crypto Demand (Phishing)",
        "type": "phishing",
        "sender": "Billing Department <accounts@quick-invoices.top>",
        "subject": "Final Notice: Invoice #INV-92819 Overdue - Legal Action Pending",
        "body": """Dear Client,

Your company's invoice #INV-92819 for server maintenance ($2,450.00) is past due.

To avoid immediate legal action and credit reporting, remit payment via Bitcoin to our company wallet within 12 hours:
BTC Wallet: 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa

Alternatively, buy Amazon gift cards and reply with the codes to settle this account.

Accounts Receivable"""
    },
    {
        "id": "sample_ambiguous_delivery",
        "title": "📦 Ambiguous Courier Notice (Suspicious)",
        "type": "suspicious",
        "sender": "Express Courier <tracking-update@delivery-hub.info>",
        "subject": "Package tracking status for parcel #US-882194",
        "body": """Hello,

We attempted to deliver your parcel today, but nobody was available to sign.

Please review your delivery preferences and update your contact information online to reschedule delivery:
https://track-courier-status.com/reschedule?id=99281

A redelivery fee of $1.50 may apply if rescheduled after 48 hours."""
    },
    {
        "id": "sample_legitimate_project",
        "title": "✅ College Project Meeting (Safe)",
        "type": "safe",
        "sender": "Prof. Alan Turing <a.turing@university.edu>",
        "subject": "Final Year Project: Meeting agenda for Tuesday lab review",
        "body": """Dear Project Team,

I hope you are making good progress on your AI Phishing Email Detection system.

Please ensure you have prepared your architecture diagrams and test coverage reports for our project lab review this Tuesday at 10:00 AM in Room 302.

Bring your laptops so we can test the local Ollama inference and rule engine live.

Best regards,
Prof. Alan Turing
Department of Computer Science
University Engineering College"""
    }
]
