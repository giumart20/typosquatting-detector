# Typosquatting Detector

A Python script designed to identify domains potentially used for typosquatting. It generates variants of a primary domain, checks their activity, and gathers detailed information such as WHOIS records, IP addresses, MX records, and SSL certificates. Additionally, it offers an option to check IPs against AbuseIPDB to detect malicious activity.

## Features

- **Domain Variant Generation**: Creates possible typosquatting variants of a given domain.
- **Domain Activity Check**: Verifies which generated domains are active.
- **Information Gathering**:
  - WHOIS records
  - IP addresses
  - MX records
  - SSL certificate details
- **AbuseIPDB Integration**: Optionally checks IP addresses against AbuseIPDB for reported malicious activity.

## Installation

1. **Clone the repository**:
   ```bash
   git clone https://github.com/giuseppemartone98/typosquatting-detector.git
   cd typosquatting-detector

2. **Create a virtual environment (optional but recommended)**:
   ```bash
   python -m venv venv
    # On Windows
    venv\Scripts\activate
    # On Unix or MacOS
    source venv/bin/activate

3. **Install the required dependencies:**:
   ```bash
   pip install -r requirements.txt

## Usage

1. **Run the script**:
   ```bash
   python typosquatting_detector.py

Follow the prompts:

Enter the primary domain (e.g., example.com).
Choose whether to check IPs against AbuseIPDB. If yes, provide your AbuseIPDB API key.

The script will display suspicious domains in the console.
Results will be saved to typosquatting_results.csv in the current directory.
