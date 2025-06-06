#!/usr/bin/python3

from imapclient import IMAPClient
import datetime
import os
import sys
import traceback
import email
import socket

import io
from zipfile import ZipFile
import gzip
import xml.etree.ElementTree as ET
import os.path
import config

messageTotalCounter = 0
msgFailTotalCounter = 0
readAllReports = False
showReportDetails = False

# Helper function to remove namespaces from an XML tree. Some providers
# include namespaces in their DMARC reports which prevents straightforward
# element lookups with ``xml.etree.ElementTree``.  Stripping the namespaces
# allows the existing XPath queries in the script to work regardless of the
# presence of namespaces.
def strip_namespace(elem):
    """Remove namespaces in the passed XML element tree in-place."""
    for el in elem.iter():
        if '}' in el.tag:
            el.tag = el.tag.split('}', 1)[1]
    return elem

def find_text(elem, path):
    """Return the text of the element at *path* or ``None`` if not found."""
    node = elem.find(path)
    return node.text if node is not None else None

def delete_messages_older_than_30_days_in_folder(server):
    # Look for messages older than 30 days
    thirty_days_ago = datetime.datetime.now() - datetime.timedelta(days=30)
    messages = server.search([u'BEFORE', thirty_days_ago])

    if len(messages) > 0:
        # Delete matching old messages
        server.delete_messages(messages)
        print(f"{len(messages)} mail(s) older than 30 days deleted..")
    else:
        print(f"No messages older than 30 days found.")

# Search for attachments
def getDMARCreportAttachment(msg):
    global messageTotalCounter
    global msgFailTotalCounter

    # Takes the raw data and breaks it into different 'parts' & python processes it 1 at a time [1]
    for part in msg.walk():
        if part.get_content_maintype() == 'multipart':  # DMARC reports are not send as "multipart"
            continue  # Skip to the next part

        if part.get('Content-Disposition') is None:  # DMARC reports are using "Content-Disposition: attachment;"
            continue  # Skip to the next part if the part is not Content-Disposition

        filename = part.get_filename()  # Get the filename
        # print("Filename: ", filename)
        if bool(filename):  # Check if filename is given
            filenameExtension = os.path.splitext(filename)[1]
            # print("file extension:", filenameExtension)

            # Decompress attachments in memory and put the file content in dataStr
            if filenameExtension == ".zip":
                dataStrCompressed = io.BytesIO(part.get_payload(decode=True))
                input_zip=ZipFile(dataStrCompressed)
                with input_zip.open(input_zip.namelist()[0], 'r') as f:
                    dataStr = f.read()
            elif filenameExtension == ".gz":
                dataStr = gzip.decompress(part.get_payload(decode=True))
            else:
                print("WARNING: %s files are not supported" % filenameExtension)
                continue

            # Read the XML tree from dataStr and remove potential namespaces
            root = ET.fromstring(dataStr)

            # Remove possible namespaces so that .find() works regardless of
            # the provider specific namespace declarations.
            strip_namespace(root)

            xml = ET.ElementTree(root)

            # Read the XML DMARC report
            try:
                reportSource = find_text(xml, "report_metadata/org_name")
                reportID = find_text(xml, "report_metadata/report_id")
                reportBeginDate = find_text(xml, "report_metadata/date_range/begin")
                reportEndDate = find_text(xml, "report_metadata/date_range/end")
                reportFromDomain = find_text(xml, "policy_published/domain")

                # If any of the mandatory fields is missing, skip this report
                if None in (reportSource, reportID, reportBeginDate, reportEndDate, reportFromDomain):
                    raise ValueError("Missing mandatory field in DMARC report")

                reportBeginDate = int(reportBeginDate)
                reportEndDate = int(reportEndDate)

                print("Report: %-14s for %12s (Period %s - %s)" % (reportSource, reportFromDomain, datetime.datetime.fromtimestamp(reportBeginDate), datetime.datetime.fromtimestamp(reportEndDate)))

                recordCount = 0
                msgReportCount = 0
                msgFailReportCount = 0
                failDetectedInReport = False
                dkimSelector = None
                for record in xml.findall("record"):
                    try:
                        recordCount += 1
                        failDetected = False
                        sourceIp = find_text(record, "row/source_ip")
                        if sourceIp is None:
                            raise ValueError("Missing source_ip in record")
                        try:
                            domainName = socket.gethostbyaddr(sourceIp)[0]
                        except  Exception as e:
                            domainName = 'No hostname found'
                            # print("Exception: %s" % str(e))

                        count = find_text(record, "row/count")
                        headerFrom = find_text(record, "identifiers/header_from")
                        count = int(count) if count is not None else 0
                        # for selector in record.findall("auth_results/dkim/selector"):
                        #     dkimSelector = selector.text
                        msgReportCount += count
                        messageTotalCounter += count

                        # Sometimes there are more than 1 dkim or spf results in 1 record
                        for dkim in record.findall("auth_results/dkim/result"):
                            if dkim.text != "pass":
                                print("      + record %d: DKIM: %s" % (recordCount, dkim.text))
                                failDetected = True

                        for spf in record.findall("auth_results/spf/result"):
                            if spf.text != "pass":
                                print("      + record %d: SPF: %s" % (recordCount, spf.text))
                                failDetected = True

                        # There is a fail detected in this record
                        if failDetected:
                            failDetectedInReport = True
                            msgFailReportCount += count
                            msgFailTotalCounter += count

                            # Show what the receiving mailserver did with the received mail(s)
                            for disposition in record.findall("row/policy_evaluated/disposition"):
                                print("      + record %d: Disposition/DMARC action: %s" % (recordCount, disposition.text))

                            print("    - record %d: FAIL: %d mail(s) send from: %s (More info at https://whatismyipaddress.com/ip/%s)" % (recordCount, count, domainName, sourceIp))
                            # print()
                        else:
                            if showReportDetails:
                                print("    - record %d: OK! %3d email(s) checked send from: %-25s (IP: %s)" % (recordCount, count, domainName, sourceIp))

                    except Exception as e:
                        print("Exception: %s" % str(e))
                        traceback.print_exc()
                        print("WARNING: Something went wrong in this record of the report")
                        failDetectedInReport = True
                if not failDetectedInReport:
                    print(" Total of %d email(s) checked and all OK!" % (msgReportCount))
                else:
                    print(" Total of %d email(s) checked and %d emails NOT passed" % (msgReportCount, msgFailReportCount))
                    failDetectedInReport = True
                print()
            except Exception as e:
                print("Exception: %s" % str(e))
                traceback.print_exc()
                print("WARNING: Something went wrong while reading the attachment with the zipped XML report")
                failDetectedInReport = True
    return failDetectedInReport

cmndLineOption = ''

for idx, arg in enumerate(sys.argv):
    if idx != 0:
        if arg == "--details":
            showReportDetails = True
        # Command line options are given
        if arg == "--all":
            readAllReports = True
        elif arg == "--test":
            readAllReports = True
            MAILBOX_FOLDER = 'Techniek/VPS/DMARC/Old'
        elif arg == "--today":
            cmndLineOption = arg
        elif arg == "--yesterday":
            cmndLineOption = arg
        elif arg == "--unread":
            cmndLineOption = arg
        if arg == "--help":
            print("DMARC analyse reports options:")
            print("    no parameters (default): Ready only unread report messages")
            print("    --details: Show also details for non error records")
            print("    --all: Read all report messages, also already processed (read) messages")
            print("    --today: Read todays report messages")
            print("    --yesterday: Read yesterdays report messages")
            print("    --unread: Read the unread report messages")
            print("    --test: Read all report messages from the Old folder")
            print("    --help: this help")
            exit(0)

with IMAPClient(config.IMAP_HOST, use_uid=True, ssl=config.IMAP_PORT) as server:  # Get the host connection with SSL security
    server.login(config.USERNAME, config.PASSWORD)  # Signing in with IMAP credentials
    server.select_folder(config.MAILBOX_FOLDER)  # Selecting mailbox folder
    print()
    print("Analyzing DMARC reports in the IMAP folder '%s' (user: %s)" % (config.MAILBOX_FOLDER, config.USERNAME))
    print()
    
    if readAllReports:
        # Read all reports in the selected folder
        messages = server.search()
        # messages = server.gmail_search("has:attachment")
    elif cmndLineOption == '--today':
        # Read todays reports in the selected folder
        messages = server.search([u'SINCE', datetime.datetime.utcnow().date()])
    elif cmndLineOption == '--yesterday':
        # Read todays reports in the selected folder
        yesterday = datetime.datetime.utcnow().date() - datetime.timedelta(days=1)
        messages = server.search([u'SINCE', yesterday])
    elif cmndLineOption == '--unread':
        # Read the unread reports in the selected folder
        messages = server.search([u'UNSEEN'])
    else:
        # Read only the unprocessed/unread reports
        # messages = server.gmail_search("has:attachment in:unread")
        messages = server.search([u'UNSEEN'])

    failDetectedInDMARCReport = False
    noDMARCreportsToProcess = False
    if len(messages) != 0:
        # response = server.fetch(messages, ['FLAGS', 'BODY', 'RFC822.SIZE', 'ENVELOPE', 'RFC822'])
        response = server.fetch(messages, ['FLAGS', 'BODY', 'ENVELOPE', 'RFC822'])

        # Process all received messages
        for msgid, data in response.items():  # Iterates through the collection and assigns to 2 variables one by one
            # print('   ID %d: flags=%s' % (msgid, data[b'FLAGS']))
            # envelope = data[b'ENVELOPE']
            # print("Mail:", envelope.subject.decode())  # Gets the subject
            envelope = data[b'ENVELOPE']
            # date = envelope.date
            # subject = envelope.subject
            # subjectArray = subject.split(' ')
            rawMsg = email.message_from_bytes(data[b'RFC822'])  # Return a message object structure from a bytes-like object[6]
            # print(rawMsg)
            if getDMARCreportAttachment(rawMsg):  # Get through the attachment(s)
                failDetectedInDMARCReport = True
            # Set the 'Seen' flag for the processed message
            server.add_flags(msgid, [b'Seen'])
    else:
        print("No DMARC reports to process in this folder")
        noDMARCreportsToProcess = True

    # Delete messages older than 30 days
    delete_messages_older_than_30_days_in_folder(server)
    # Save changes to the folder
    server.expunge()
    server.logout()  # Ensures a logout

print()
print("DMARC analyse summary:")
print(" - Total DMARC report mails processed: %d " % len(messages))
print(" - Nr of messages checked: %2d" % messageTotalCounter)
print(" - Nr of messages passed:  %2d" % (messageTotalCounter - msgFailTotalCounter))
print(" - Nr of messages failed:  %2d" % msgFailTotalCounter)
print()

if failDetectedInDMARCReport:
    exit(1) # ERROR: Problems detected
else:
    if not noDMARCreportsToProcess:
        exit(0) # OK: All emails OK
    else:
        exit(2) # WARNING: No DMARC reports to process in this folder
