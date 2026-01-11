import re
import hashlib
import ipaddress
import requests
import email
import json
import os
import argparse

with open('.env', 'rb') as file:
    key = file.read().strip()

def read_file(file_path):
    with open(file_path, 'rb') as file:
        content = file.read()
    parser = email.parser.BytesParser()
    msg = parser.parsebytes(content)
    return msg

def extract_ips(email_message):
    ips = set()
    
    # Extract IP addresses from headers
    for header_name, header_value in email_message.items():
        ips.update(re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', header_value))
    
    # Extract IP addresses from email body
    for part in email_message.walk():
        content_type = part.get_content_type()
        if content_type == 'text/plain' or content_type == 'text/html':
            payload = part.get_payload(decode=True)
            if isinstance(payload, bytes):
                payload = payload.decode('utf-8', errors='ignore')
            ips.update(re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', payload))
    
    valid_ips = []
    for ip in ips:
        try:
            ipaddress.ip_address(ip)
            valid_ips.append(ip)
        except ValueError:
            pass
    return list(set(valid_ips))

def extract_urls(email_message):
    urls = set()
    for part in email_message.walk():
        content_type = part.get_content_type()
        if content_type == 'text/plain' or content_type == 'text/html':
            payload = part.get_payload(decode=True)
            if isinstance(payload, bytes):
                payload = payload.decode('utf-8', errors='ignore')
            urls.update(re.findall(r'https?:\/\/(?:[\w\-]+\.)+[a-z]{2,}(?:\/[\w\-\.\/?%&=]*)?', payload))
    return list(urls)

def defang_ip(ip):
    return ip.replace('.', '[.]')

def defang_url(url):
    url = url.replace('https://', 'hxxps[://]')
    url = url.replace('http://', 'hxxp[://]')
    url = url.replace('.', '[.]')
    return url

def is_reserved_ip(ip):
    private_ranges = [
        '10.0.0.0/8',
        '172.16.0.0/12',
        '192.168.0.0/16',
    ]
    reserved_ranges = [
        '0.0.0.0/8',
        '100.64.0.0/10',
        '169.254.0.0/16',
        '192.0.0.0/24',
        '192.0.2.0/24',
        '198.51.100.0/24',
        '203.0.113.0/24',
        '224.0.0.0/4', 
        '240.0.0.0/4',
    ]
    for r in private_ranges + reserved_ranges:
        if ipaddress.ip_address(ip) in ipaddress.ip_network(r):
            return True
    return False

def ip_lookup(ip):
    if is_reserved_ip(ip):
        return None
    try:
        url = f"https://ipinfo.io/{ip}/json"
        response = requests.get(url, timeout=5)
        if response.status_code == 200:
            data = response.json()
            return {
                'IP': data.get('ip', ''),
                'City': data.get('city', ''),
                'Region': data.get('region', ''),
                'Country': data.get('country', ''),
                'Location': data.get('loc', ''),
                'ISP': data.get('org', ''),
                'Postal Code': data.get('postal', '')
            }
    except (requests.RequestException, ValueError) as e:
        print(f"[-] Error: {e}")
    return None

def ip_abuse(ip):
    try:
        if is_reserved_ip(ip):
            return None
        url = 'https://api.abuseipdb.com/api/v2/check'

        querystring = {
            'ipAddress': ip,
            'maxAgeInDays': '90'
        }

        headers = {
            'Accept': 'application/json',
            'Key': key
        }

        response = requests.request(method='GET', url=url, headers=headers, params=querystring)

        return json.loads(response.text)
    except (requests.RequestException, ValueError) as e:
        print(f"[-] Error: {e}")
    return None



def extract_headers(email_message):
    headers_to_extract = [
        "Date",
        "Subject",
        "To",
        "From",
        "Reply-To",
        "Return-Path",
        "Message-ID",
        "X-Originating-IP",
        "X-Sender-IP",
        "Authentication-Results"
    ]
    headers = {}
    for key in email_message.keys():
        if key in headers_to_extract:
            headers[key] = email_message[key]
    return headers

def extract_attachments(email_message, dump_dir):
    attachments = []
    dumped = []  # Create Directory to dump attachment into
    for part in email_message.walk():
        if part.get_content_maintype() == 'multipart':
            continue
        if part.get('Content-Disposition') is None:
            continue
        filename = part.get_filename()
        if filename:
            contents = part.get_payload(decode=True)
            attachments.append({
                'filename': filename,
                'md5': hashlib.md5(contents).hexdigest(),
                'sha1': hashlib.sha1(contents).hexdigest(),
                'sha256': hashlib.sha256(contents).hexdigest()
            })

            # Dump the attachments
            if dump:
                try:
                    os.mkdir(dump_dir)
                except FileExistsError:
                    pass
                except Exception as e:
                    print(f"[-] Failed to create '{dump_dir}' Directory: {e}")

                with open(f"{dump_dir}/{filename}", 'wb') as file:
                    file.write(contents)
                dumped.append(f"[+] Attachment Successfully Dumped to '{dump_dir}/{filename}'")


    return attachments, dumped

def format_last_report(last_report):
    try:
        last_report = last_report.split("T", 1)
        last_report_date = last_report[0]
        last_report_time = last_report[1].split("+")[0]
        return last_report_date, last_report_time
    except AttributeError:
        # Data not available (there are no reports)
        return "N/A", "N/A"


def main(file_path, dump_dir):
    email_message = read_file(file_path)
    ips = extract_ips(email_message)
    urls = extract_urls(email_message)
    headers = extract_headers(email_message)
    attachments, dumped = extract_attachments(email_message, dump_dir)

    print("Extracted IP Addresses:")
    print("====================================")
    for ip in ips:
        defanged_ip = defang_ip(ip)
        ip_info = ip_lookup(ip)
        ip_abuse_info = ip_abuse(ip)

        if ip_info:
            print(f"{defanged_ip}\n    Location: {ip_info['City']}, {ip_info['Region']}, {ip_info['Country']}")
            print(f"    ISP: {ip_info['ISP']}")
        if ip_abuse_info:
            print(f"    Tor Exit Node: {ip_abuse_info['data']['isTor']}")
            print(f"    Domain: {ip_abuse_info['data']['domain']}")
            print(f"    Abuse Score: {ip_abuse_info['data']['abuseConfidenceScore']}%")
            print(f"    Number of reports: {ip_abuse_info['data']['totalReports']}")
            last_report = ip_abuse_info['data']['lastReportedAt']
            last_report_date, last_report_time = format_last_report(last_report)
            print(f"    Last Reported on: {last_report_date} At {last_report_time}\n")

        else:
            print(defanged_ip)

    if urls:  # if there are urls extracted from email
        print("\nExtracted URLs:")
        print("====================================")
    for url in urls:
        print(defang_url(url))

    print("\nExtracted Headers:")
    print("====================================")
    for key, value in headers.items():
        print(f"{key}: {value}")

    if attachments:  # if there are attachments extracted from email
        print("\nExtracted Attachments:")
        print("====================================")
    for attachment in attachments:
        print(f"Filename: {attachment['filename']}")
        print(f"MD5: {attachment['md5']}")
        print(f"SHA1: {attachment['sha1']}")
        print(f"SHA256: {attachment['sha256']}")
        print()

    if dumped:  # Attachments have been dumped
        for msg in dumped:
            print(msg)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        prog="eioc",
        description="This Python script is designed to aid in email forensic analysis by extracting various components from email files such as IP addresses, URLs, headers, and attachments."
    )
    parser.add_argument('file', help="The email file to analyse")
    parser.add_argument('--dump', default=False, help="The directory in which to dump the email attachments")

    args = parser.parse_args()

    if args.dump:
        dump = True
    else:
        dump = False
    main(args.file, args.dump)
