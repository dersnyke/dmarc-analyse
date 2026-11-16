"""Offline regression checks for the complete mail-processing path."""

import contextlib
import gzip
import io
import runpy
import sys
import types
import unittest
import zipfile
from email.message import EmailMessage
from pathlib import Path
from unittest.mock import patch


SCRIPT = Path(__file__).with_name("dmarc-analyse.py")
GOOD_XML = b"""<feedback><report_metadata><org_name>Example</org_name>
<report_id>r1</report_id><date_range><begin>1700000000</begin>
<end>1700086400</end></date_range></report_metadata>
<policy_published><domain>example.com</domain></policy_published>
<record><row><source_ip>127.0.0.1</source_ip><count>2</count></row>
<auth_results><dkim><result>pass</result></dkim>
<spf><result>pass</result></spf></auth_results></record></feedback>"""
BAD_XML = GOOD_XML.replace(b"<org_name>Example</org_name>", b"").replace(
    b"<domain>example.com</domain>", b""
)


def zip_xml(data):
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w") as archive:
        archive.writestr("report.xml", data)
    return output.getvalue()


def run_mail(attachments):
    message = EmailMessage()
    message["From"] = "reports@example.com"
    message["To"] = "admin@example.com"
    message.set_content("DMARC report")
    for filename, payload in attachments:
        message.add_attachment(payload, maintype="application", subtype="octet-stream", filename=filename)

    class FakeIMAP:
        def __init__(self, host, use_uid, ssl):
            assert (host, use_uid, ssl) == ("example.invalid", True, 993)

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            pass

        def login(self, username, password):
            assert (username, password) == ("user", "password")

        def select_folder(self, folder):
            assert folder == "DMARC"

        def search(self, criteria=None):
            return [1] if criteria == ["UNSEEN"] else []

        def fetch(self, ids, fields):
            assert ids == [1] and fields == ["RFC822"]
            return {1: {b"RFC822": message.as_bytes()}}

        def add_flags(self, msgid, flags):
            assert (msgid, flags) == (1, [b"Seen"])

        def expunge(self):
            pass

        def logout(self):
            pass

    config = types.ModuleType("config")
    config.IMAP_HOST = "example.invalid"
    config.IMAP_PORT = 993
    config.USERNAME = "user"
    config.PASSWORD = "password"
    config.MAILBOX_FOLDER = "DMARC"
    imapclient = types.ModuleType("imapclient")
    imapclient.IMAPClient = FakeIMAP

    stdout = io.StringIO()
    stderr = io.StringIO()
    with patch.dict(sys.modules, {"config": config, "imapclient": imapclient}), \
         patch.object(sys, "argv", [str(SCRIPT)]), \
         contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
        with self_exit_code() as code:
            runpy.run_path(str(SCRIPT), run_name="__main__")
    return code[0], stdout.getvalue(), stderr.getvalue()


@contextlib.contextmanager
def self_exit_code():
    code = []
    try:
        yield code
    except SystemExit as exc:
        code.append(exc.code)
    else:
        code.append(0)


class MailProcessingTests(unittest.TestCase):
    def test_supported_report_formats(self):
        for filename, payload in (
            ("report.xml", GOOD_XML),
            ("report.XML", GOOD_XML),
            ("report.zip", zip_xml(GOOD_XML)),
            ("report.gz", gzip.compress(GOOD_XML)),
        ):
            with self.subTest(filename=filename):
                code, output, errors = run_mail([(filename, payload)])
                self.assertEqual(code, 0, errors)
                self.assertIn("Total of 2 email(s) checked and all OK!", output)
                self.assertIn("Nr of messages checked:  2", output)

    def test_unsupported_attachment_still_finishes(self):
        code, output, errors = run_mail([("notes.txt", b"not a report")])
        self.assertEqual(code, 0, errors)
        self.assertIn("IMAP UID 1, attachment 'notes.txt': .txt files are not supported", output)
        self.assertIn("DMARC analyse summary:", output)

    def test_bad_report_failure_survives_later_good_report(self):
        code, output, errors = run_mail([
            ("bad.xml", BAD_XML),
            ("good.xml", GOOD_XML),
        ])
        self.assertEqual(code, 1)
        self.assertIn("IMAP UID 1, attachment 'bad.xml': Missing DMARC fields: ", output)
        self.assertIn("report_metadata/org_name", output)
        self.assertIn("policy_published/domain", output)
        self.assertEqual(errors, "")
        self.assertIn("Total of 2 email(s) checked and all OK!", output)
        self.assertIn("Nr of messages checked:  2", output)

    def test_unused_report_id_is_optional(self):
        xml_without_id = GOOD_XML.replace(b"<report_id>r1</report_id>", b"")
        code, output, errors = run_mail([("no-id.xml", xml_without_id)])
        self.assertEqual(code, 0, errors)
        self.assertIn("Total of 2 email(s) checked and all OK!", output)

    def test_malformed_xml_does_not_prevent_summary(self):
        code, output, errors = run_mail([("broken.xml", b"<feedback>")])
        self.assertEqual(code, 1)
        self.assertIn("IMAP UID 1, attachment 'broken.xml': Could not read", output)
        self.assertIn("DMARC analyse summary:", output)
        self.assertIn("ParseError", errors)


if __name__ == "__main__":
    unittest.main()
