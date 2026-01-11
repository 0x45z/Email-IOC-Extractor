# Email IOC Extractor
This Python script is designed to aid in email forensic analysis by extracting various components from email files such as IP addresses, URLs, headers, and attachments.

## Features:
- **IP Address Extraction**: Identifies and extracts IP addresses from the email content in defanged format.
- **URL Extraction**: Extracts URLs from the email content in defanged format.
- **Header Extraction**: Retrieves common useful email headers to aid in sender attribution.
- **Attachment Extraction**: Parses, and optionally dumps, email attachments and provides details such as filename, MD5, SHA1, and SHA256 hashes.

## Additional Functionalities:
- **IP and URL Defanging**: Defangs IP addresses and URLs, making them safer for analysis.
- **IP Information Lookup**: Utilizes the `ipinfo.io` API to gather information about IP addresses, including city, region, country, and ISP.
- **IP Information Lookup**: Utilizes the `AbuseIPDB` API to gather information on abuse reports of IP addresses. This will report on IP's that are known to be used in malicious ways.

## Requirements

```bash
pip3 install -r requirements.txt
```

## Usage
```bash
python3 eioc.py <file_path>
python3 eioc.py <file_path> --dump <path_to_dump>
```

Example:
```bash
$ python3 eioc.py sample1.eml 
Extracted IP Addresses:
====================================
192[.]53[.]121[.]84
    Location: Toronto, Ontario, CA
    ISP: AS63949 Akamai Connected Cloud
    Tor Exit Node: False
    Domain: linode.com
    Abuse Score: 0%
    Number of reports: 0
    Last Reported on: 2023-08-02 At 08:07:36

10[.]233[.]255[.]248

Extracted URLs:
====================================
hxxps[://]http2[.]mlstatic[.]com/static/org-img/mkt/email-mkt-assets/davinci/2x/logo-meli-br
hxxps[://]n-a4qxna7jwq-rj[.]a[.]run[.]app/m/?tr=33a802771d3b43e0b002f9f5e20f5f2f&amp

Extracted Headers:
====================================
Authentication-Results: spf=none (sender IP is 192.53.121.84)
 smtp.mailfrom=mercadolivre.br; dkim=fail (no key for signature)
 header.d=goodbuild.com;dmarc=none action=none
 header.from=mercadolivre.br;compauth=fail reason=001
From: Mercado Livre <notificacoes@mercadolivre.br>
To: phishing@pot
Subject: BLOQUEAMOS UM ACESSO SUSPEITO - PROTOCOLO: 262677886
Message-ID: <04418440-957a-c8df-171f-05ae3fcdec24@mercadolivre.br>
Date: Tue, 08 Aug 2023 17:44:15 +0000
Return-Path: notificacoes@mercadolivre.br
X-Sender-IP: 192.53.121.84
```

```bash
$ python3 eioc.py sample1.eml --dump extracted_attachments
Extracted IP Addresses:
====================================
209[.]85[.]160[.]41
    Location: Tulsa, Oklahoma, US
    ISP: AS15169 Google LLC
    Tor Exit Node: False
    Domain: google.com
    Abuse Score: 49%
    Number of reports: 24
    Last Reported on: 2026-01-10 At 02:59:12

10[.]13[.]172[.]217

Extracted Headers:
====================================
Authentication-Results: spf=none (sender IP is 209.85.160.41)
 smtp.mailfrom=freeducation.co.uk; dkim=pass (signature was verified)
 header.d=freeducation-co-uk.20221208.gappssmtp.com;dmarc=none action=none
 header.from=freeducation.co.uk;
From: "support@inlt.payp... .com" <cscservdab-01774233358@freeducation.co.uk>
Date: Mon, 7 Aug 2023 04:55:46 +0800
Message-ID: <CADi0ko-tPf0tWWHSJoXxS68EBrbkU9AX8ki1wjstOd93E6Hw5w@mail.gmail.com>
Subject: Action required for validate. Ref-325234325
To: undisclosed-recipients:;
Return-Path: cscservdab-01774233358@freeducation.co.uk
X-Sender-IP: 209.85.160.41

Extracted Attachments:
====================================
Filename: DocumentActionRequired-(PP)#645764584 (11).pdf
MD5: c0d414e0c098d351b3e12e2d9c231b30
SHA1: eae3e7f2b979c3700aa662cd7b36301df74d9fb3
SHA256: fda084d7e7ff81442eaa28b7297d07ec1193f7e9e0ae40db305ab7a83ae0dda4

[+] Attachment Successfully Dumped to 'extracted_attachments/DocumentActionRequired-(PP)#645764584 (11).pdf'

```
## Compatibility:
This script is compatible with Python 3.x.

## Disclaimer:
This tool is intended for analysis and research purposes only. Usage should comply with applicable laws and regulations.

