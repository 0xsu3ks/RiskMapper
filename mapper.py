import openai
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import plotly.graph_objects as go
from fpdf import FPDF
import requests
import argparse
import configparser
from datetime import datetime
import os
import io

import warnings
# Suppress specific warnings
warnings.filterwarnings("ignore", category=UserWarning)         # Suppress UserWarnings (e.g., FPDF font substitution)
warnings.filterwarnings("ignore", category=FutureWarning)       # Suppress FutureWarnings (e.g., deprecated methods)
warnings.filterwarnings("ignore", category=DeprecationWarning)  # Suppress DeprecationWarnings (e.g., ln parameter)
warnings.filterwarnings("ignore", message="urllib3")            # Suppress urllib3-related warnings
import urllib3
warnings.simplefilter("ignore", category=urllib3.exceptions.NotOpenSSLWarning)


def print_ascii_art():
    ascii_art = r"""
  __  __ _____ _______ _____  ______   __  __          _____  _____  ______ _____  
 |  \/  |_   _|__   __|  __ \|  ____| |  \/  |   /\   |  __ \|  __ \|  ____|  __ \ 
 | \  / | | |    | |  | |__) | |__    | \  / |  /  \  | |__) | |__) | |__  | |__) |
 | |\/| | | |    | |  |  _  /|  __|   | |\/| | / /\ \ |  ___/|  ___/|  __| |  _  / 
 | |  | |_| |_   | |  | | \ \| |____  | |  | |/ ____ \| |    | |    | |____| | \ \ 
 |_|  |_|_____|  |_|  |_|  \_\______| |_|  |_/_/    \_\_|    |_|    |______|_|  \_\
                                                                                   
 
  MITRE ATT&CK Coverage Analysis Tool - RiskMapper
                        Authors:
                            + Kevin Suckiel (0xsu3ks)
                            + Yuval Nitzan
                            + Alexandra Leslie
  -------------------------------------------------
    """
    print(ascii_art)

# Call this function at the start of your script
#print_ascii_art()


def load_config(config_file='config.ini'):
    """Load configuration from a .ini file."""
    config = configparser.ConfigParser()
    config.read(config_file)
    return config

def setup_openai_api(config):
    """Setup OpenAI API using the key from the config."""
    openai.api_key = config.get("OpenAI", "api_key")

def query_chatgpt(url):
    """Use ChatGPT API to extract MITRE mappings from the given PDF URL."""
    prompt = f"Please analyze the following PDF report and extract MITRE ATT&CK techniques, tactics, and threat group mappings:\n{url}"
    
    response = openai.ChatCompletion.create(
        model="gpt-4o-mini",
        messages=[{"role": "user", "content": prompt}],
        max_tokens=1500
    )
    
    content = response['choices'][0]['message']['content']
    return content

def parse_urls_from_input():
    """Read URLs interactively from stdin."""
    print("Enter URLs (one per line). Type 'done' to finish:")
    urls = []
    while True:
        url = input()
        if url.lower() == 'done':
            break
        urls.append(url)
    return urls

def parse_urls_from_file(file_path):
    """Read URLs from a file."""
    with open(file_path, 'r') as file:
        urls = [line.strip() for line in file if line.strip()]
    return urls

def process_pdf_urls(urls):
    """Process each URL to extract MITRE mappings and generate a Threat Report."""
    data = []
    
    for url in urls:
        print(f"Processing URL: {url}")
        try:
            content = query_chatgpt(url)
            print("Extracted Data:", content)

            for line in content.split("\n"):
                parts = line.split("\t")
                if len(parts) == 7:
                    data.append({
                        "Observed Activity": parts[0],
                        "MITRE ATT&CK Technique": parts[1],
                        "Technique ID": parts[2],
                        "Tactic": parts[3],
                        "Severity": parts[4],
                        "Detected": parts[5],
                        "Threat Group": parts[6]
                    })
        except Exception as e:
            print(f"Error processing {url}: {e}")
    
    return pd.DataFrame(data)

def generate_threat_report(df, output_prefix):
    """Generate an Excel file for the Threat Report."""
    if not df.empty:
        filename = f"{output_prefix}_Threat_Report_{datetime.now().strftime('%Y%m%d')}.xlsx"
        df.to_excel(filename, index=False)
        print(f"Threat Report generated: {filename}")
        return filename
    else:
        print("No data to generate Threat Report.")
        return None

def load_data(threat_report_file, controls_file):
    """Load data from Excel files."""
    threat_df = pd.read_excel(threat_report_file)
    controls_df = pd.read_excel(controls_file)
    return threat_df, controls_df

def analyze_coverage(threat_df, controls_df):
    """Analyze control coverage against threat data."""
    merged_df = pd.merge(threat_df, controls_df, on='Technique ID', how='left')
    coverage_percentage = (merged_df['Coverage Status'] == 'Yes').mean() * 100
    return merged_df, coverage_percentage

import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import plotly.graph_objects as go
from fpdf import FPDF
from datetime import datetime

def generate_charts(merged_df, output_prefix):
    """Generate various charts and save them as images."""
    sns.set(style="whitegrid")

    # 1. Coverage Status Pie Chart
    plt.figure(figsize=(6, 4))
    coverage_count = merged_df['Coverage Status'].value_counts()
    coverage_count.plot.pie(autopct='%1.1f%%', colors=['#4CAF50', '#F44336'])
    plt.title("Coverage Status")
    plt.ylabel('')
    plt.savefig(f"{output_prefix}_coverage_status_pie.png")
    plt.close()

    # 2. Control Effectiveness Bar Chart
    plt.figure(figsize=(8, 5))
    sns.countplot(data=merged_df, x='Effectiveness', order=merged_df['Effectiveness'].value_counts().index)
    plt.title("Control Effectiveness")
    plt.xlabel("Effectiveness Level")
    plt.ylabel("Count")
    plt.savefig(f"{output_prefix}_control_effectiveness_bar.png")
    plt.close()

    # 3. Heatmap of Coverage by Tactic
    plt.figure(figsize=(10, 6))
    tactic_coverage = pd.crosstab(merged_df['Tactic_y'], merged_df['Coverage Status'])
    sns.heatmap(tactic_coverage, cmap="YlGnBu", annot=True, fmt='d')
    plt.title("Coverage by Tactic")
    plt.savefig(f"{output_prefix}_tactic_coverage_heatmap.png")
    plt.close()

    # 4. Horizontal Bar Chart for Activities by Threat Group
    plt.figure(figsize=(10, 6))
    sns.countplot(data=merged_df, y='Threat Group', order=merged_df['Threat Group'].value_counts().index)
    plt.title("Activities by Threat Group")
    plt.xlabel("Count")
    plt.ylabel("Threat Group")
    plt.savefig(f"{output_prefix}_threat_group_bar.png")
    plt.close()

    # 5. MITRE ATT&CK Heatmap
    plt.figure(figsize=(12, 8))
    mitre_heatmap_data = pd.crosstab(merged_df['Tactic_y'], merged_df['Technique ID'], values=merged_df['Coverage Status'], aggfunc=lambda x: 'Covered' if 'Yes' in x.values else 'Not Covered')
    sns.heatmap(pd.get_dummies(mitre_heatmap_data), cmap='coolwarm', annot=True)
    plt.title("MITRE ATT&CK Heatmap")
    plt.savefig(f"{output_prefix}_mitre_heatmap.png")
    plt.close()

    # 6. Stacked Bar Chart for Detected vs. Undetected Activities by Severity
    severity_detection = merged_df.groupby(['Severity', 'Detected']).size().unstack(fill_value=0)
    severity_detection.plot(kind='bar', stacked=True, figsize=(10, 6), colormap='viridis')
    plt.title("Detected vs. Undetected Activities by Severity")
    plt.xlabel("Severity")
    plt.ylabel("Count")
    plt.legend(title="Detected")
    plt.savefig(f"{output_prefix}_severity_detection_stacked_bar.png")
    plt.close()

def create_pdf_report(company_name, ciso_name, coverage_percentage, output_prefix):
    """Create a PDF report with charts."""
    pdf = FPDF()
    pdf.add_page()

    # Add headers
    pdf.set_font("Arial", 'B', 16)
    pdf.cell(200, 10, txt=f"MITRE ATT&CK Coverage Analysis for {company_name}", ln=True, align='C')
    pdf.cell(200, 10, txt=f"CISO: {ciso_name}", ln=True, align='C')
    pdf.cell(200, 10, txt=f"Coverage Percentage: {coverage_percentage:.2f}%", ln=True)

    # Add main charts to PDF
    pdf.image(f"{output_prefix}_coverage_status_pie.png", x=10, w=100)
    pdf.image(f"{output_prefix}_control_effectiveness_bar.png", x=10, w=120)
    pdf.image(f"{output_prefix}_tactic_coverage_heatmap.png", x=10, w=150)
    pdf.image(f"{output_prefix}_threat_group_bar.png", x=10, w=150)
    pdf.image(f"{output_prefix}_mitre_heatmap.png", x=10, w=150)
    pdf.image(f"{output_prefix}_severity_detection_stacked_bar.png", x=10, w=150)

    # Add additional charts to PDF
    pdf.add_page()
    pdf.image(f"{output_prefix}_fully_implemented_controls.png", x=10, w=120)
    pdf.image(f"{output_prefix}_not_implemented_controls.png", x=10, w=120)

    # Save PDF
    pdf_file = f"{output_prefix}_Coverage_Report_{datetime.now().strftime('%Y%m%d')}.pdf"
    pdf.output(pdf_file)
    print(f"PDF Report generated: {pdf_file}")


import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns

def generate_additional_charts(controls_df, output_prefix):
    """Generate charts to highlight fully implemented and not implemented controls."""
    sns.set(style="whitegrid")

    # Filter fully implemented controls by control type
    fully_implemented_df = controls_df[controls_df['Effectiveness'] == 'Fully Implemented']
    implemented_count = fully_implemented_df['Control Type'].value_counts()

    # 1. Bar Chart: Count of Fully Implemented Controls by Control Type
    plt.figure(figsize=(8, 5))
    sns.barplot(x=implemented_count.index, y=implemented_count.values, palette='viridis')
    plt.title("Count of Fully Implemented Controls by Control Type")
    plt.xlabel("Control Type")
    plt.ylabel("Number of Controls")
    plt.xticks(rotation=45)
    plt.tight_layout()
    plt.savefig(f"{output_prefix}_fully_implemented_controls.png")
    plt.close()

    # Filter controls that are not implemented
    not_implemented_df = controls_df[controls_df['Effectiveness'] == 'Not Implemented']
    not_implemented_count = not_implemented_df['Control Type'].value_counts()

    # 2. Pie Chart: Controls Not Implemented by Control Type
    plt.figure(figsize=(6, 6))
    not_implemented_count.plot(kind='pie', autopct='%1.1f%%', colors=['#F44336', '#FF9800', '#9C27B0'])
    plt.title("Controls Not Implemented by Control Type")
    plt.ylabel('')
    plt.tight_layout()
    plt.savefig(f"{output_prefix}_not_implemented_controls.png")
    plt.close()

    print("Additional charts generated successfully.")


def main():
    print_ascii_art()  # Display ASCII art at the start

    parser = argparse.ArgumentParser(description="MITRE Analysis and Threat Report Generator")
    parser.add_argument("--interactive", action='store_true', help="Interactive mode to input URLs")
    parser.add_argument("--feed", type=str, help="Path to a file containing URLs")
    parser.add_argument("--tr", type=str, help="Path to an existing Threat Report Excel file")
    parser.add_argument("--cr", type=str, help="Path to Controls Assessment Excel file")
    args = parser.parse_args()

    config = load_config()
    setup_openai_api(config)

    output_prefix = config.get("Output", "output_filename_prefix")
    company_name = config.get("CompanyInfo", "company_name")
    ciso_name = config.get("CompanyInfo", "ciso_name")

    # Determine the source of the Threat Report
    if args.interactive or args.feed:
        urls = parse_urls_from_input() if args.interactive else parse_urls_from_file(args.feed)
        df = process_pdf_urls(urls)
        threat_report_file = generate_threat_report(df, output_prefix)
    elif args.tr:
        threat_report_file = args.tr
    else:
        print("Please provide either --interactive, --feed, or --tr")
        return

    controls_report_file = args.cr or config.get("Files", "controls_report_filename")
    threat_df, controls_df = load_data(threat_report_file, controls_report_file)
    merged_df, coverage_percentage = analyze_coverage(threat_df, controls_df)

    # Generate charts and reports
    generate_charts(merged_df, output_prefix)
    generate_additional_charts(controls_df, output_prefix)
    create_pdf_report(company_name, ciso_name, coverage_percentage, output_prefix)

if __name__ == "__main__":
    main()

