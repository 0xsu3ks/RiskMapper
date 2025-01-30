# MITRE ATT&CK Coverage Analysis Tool - RiskMapper
## Overview

RiskMapper is a tool designed to analyze and report the coverage of MITRE ATT&CK techniques, tactics, and threat group mappings from provided PDF reports. It uses the OpenAI API to extract this information and generates a comprehensive threat report, including visual charts and a PDF summary.
Table of Contents
```
    Features
    Installation
    Configuration
    Usage
    Examples
    Authors
```

### Features

    Extract MITRE ATT&CK mappings from PDF reports using OpenAI API.
    Generate threat reports in Excel format.
    Analyze control coverage against threat data.
    Generate various visual charts for data analysis.
    Create a comprehensive PDF report with visual charts.

### Installation

    Clone the repository:
    bash

`git clone https://github.com/yourusername/riskmapper.git`
`cd riskmapper`

Install the required dependencies:

`pip install -r requirements.txt`

Set up your environment:
    + Ensure you have Python 3.6 or higher installed.
    + Install additional system packages if needed (e.g., for fpdf or seaborn).

### Configuration

Create a config.ini file in the root directory with the following structure:
```
[OpenAI]
api_key = your_openai_api_key

[Output]
output_filename_prefix = your_output_prefix

[CompanyInfo]
company_name = Your Company Name
ciso_name = Your CISO Name

[Files]
controls_report_filename = path_to_controls_report.xlsx
```

### Usage

The tool can be used in different modes (interactive, file-based, or using existing reports):

Interactive Mode:    

`python riskmapper.py --interactive`

Feed URLs from a File:

`python riskmapper.py --feed urls.txt`

Using an Existing Threat Report:

`python riskmapper.py --tr existing_threat_report.xlsx`

Specify Controls Report (Optional):

`python riskmapper.py --cr controls_report.xlsx`

### Examples
Run in Interactive Mode

`python riskmapper.py --interactive`

Run with URLs from a File

`python riskmapper.py --feed urls.txt`

Run with Existing Threat Report and Controls Report

`python riskmapper.py --tr existing_threat_report.xlsx --cr controls_report.xlsx`

Authors:

+ Kevin Suckiel (0xsu3ks)
+ Yuval Nitzan
+ Alexandra Leslie
