#!/usr/bin/env python3
"""
Generate the analytics report for the crawler assignment.
Run this script after the crawler has completed.
"""

import json
import os
from collections import Counter

def generate_report():
    analytics_file = "analytics_data.json"
    
    if not os.path.exists(analytics_file):
        print("Error: analytics_data.json not found. Run the crawler first.")
        return
    
    with open(analytics_file, 'r') as f:
        data = json.load(f)
    
    # Create report
    report = []
    report.append("=" * 80)
    report.append("WEB CRAWLER ANALYTICS REPORT")
    report.append("=" * 80)
    report.append("")
    
    # Question 1: Number of unique pages
    unique_count = len(data['unique_urls'])
    report.append(f"1. Number of unique pages found: {unique_count}")
    report.append("")
    
    # Question 2: Longest page
    longest = data['longest_page']
    report.append(f"2. Longest page:")
    report.append(f"   URL: {longest['url']}")
    report.append(f"   Word count: {longest['word_count']}")
    report.append("")
    
    # Question 3: 50 most common words
    report.append("3. 50 most common words (excluding stop words):")
    word_freq = data['word_freq']
    most_common = Counter(word_freq).most_common(50)
    for i, (word, freq) in enumerate(most_common, 1):
        report.append(f"   {i:2d}. {word:20s} - {freq:,}")
    report.append("")
    
    # Question 4: Subdomains
    report.append("4. Subdomains in uci.edu domain:")
    subdomains = data['subdomains']
    # Sort alphabetically
    sorted_subdomains = sorted(subdomains.items())
    for subdomain, count in sorted_subdomains:
        report.append(f"   {subdomain}, {count}")
    report.append("")
    
    report.append("=" * 80)
    
    # Print to console
    report_text = "\n".join(report)
    print(report_text)
    
    # Save to file
    with open("REPORT.txt", "w") as f:
        f.write(report_text)
    
    print("\nReport saved to REPORT.txt")

if __name__ == "__main__":
    generate_report()
