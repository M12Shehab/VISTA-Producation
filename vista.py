"""
 __author__ = "Mohammed Shehab"
 __copyright__ = "Copyright (c) 2024 Mohammed Shehab"
 __credits__ = ["Mohammed Shehab", "Safwan Omari", "Yaser Jararweh"]
 __license__ = "MIT License"
 __version__ = "1.0.0"
 __maintainer__ = "Mohammed Shehab"
 __email__ = "shihab@live.cn"
 __status__ = "Development"
"""
import argparse

import matplotlib.pyplot as plt
import statistics
import time
from collections import defaultdict
from datetime import datetime

import requests

from modules.DataHandler import DataHandler
from modules.GitRepository import GitRepository
from modules.VulnerabilityAnalyzer import VulnerabilityAnalyzer
from modules.VulnerabilityFetcher import VulnerabilityFetcher
from modules.CommitLoader import CommitLoader
from modules.CommitAnalyzer import CommitAnalyzer
from modules.CommitLabeler import CommitLabeler
from modules.configuration import project_name, repo_url, code_repository_path, repository_branch, num_workers, \
    nvd_api_key
from modules.System_logging import setup_project_logger
from modules.CommitProcessor import CommitProcessor
import pandas as pd
from modules.VulnerabilityScanner import VulnerabilityScanner

api_key = nvd_api_key
severity = None

log = setup_project_logger(project_name)

# Todo: in case you change the data directory, you need to update the base_dir also
data_control = DataHandler(base_dir='./data')


def print_vulnerability_statistics(data):
    # Initialize statistics containers
    total_vulnerabilities = len(set(item['bug_pattern'] for item in data))
    severity_counts = defaultdict(int)
    vulnerability_lifespans = []

    for item in data:
        # Count severity levels
        severity_counts[item['severity']] += 1

        # Calculate vulnerability lifespan in days
        vulnerable_time = datetime.strptime(item['vulnerable_time'], "%Y-%m-%d %H:%M:%S")
        fixing_time = datetime.strptime(item['fixing_time'], "%Y-%m-%d %H:%M:%S")
        lifespan = (fixing_time - vulnerable_time).days
        vulnerability_lifespans.append(lifespan)

    # Calculate average lifespan
    average_lifespan = sum(vulnerability_lifespans) / len(vulnerability_lifespans) if vulnerability_lifespans else 0

    # Calculate additional time statistics
    total_lifespan = sum(vulnerability_lifespans)
    min_lifespan = min(vulnerability_lifespans) if vulnerability_lifespans else 0
    max_lifespan = max(vulnerability_lifespans) if vulnerability_lifespans else 0
    median_lifespan = statistics.median(vulnerability_lifespans) if vulnerability_lifespans else 0

    # Print statistics
    print("Vulnerability Statistics:")
    print(f"Total Unique Vulnerabilities: {total_vulnerabilities}")
    print(f"Average Vulnerability Lifespan (days): {average_lifespan:.2f}")
    print(f"Total Vulnerability Lifespan (days): {total_lifespan}")
    print(f"Minimum Vulnerability Lifespan (days): {min_lifespan}")
    print(f"Maximum Vulnerability Lifespan (days): {max_lifespan}")
    print(f"Median Vulnerability Lifespan (days): {median_lifespan}")
    print("Severity Counts:")
    for severity, count in severity_counts.items():
        print(f"  {severity}: {count}")


def compare_vulnerabilities(szz_results, cppcheck_results):
    # Index V-SZZ data by hash_introduced for quick lookups
    vszz_index = {item['hash_introduced']: item for item in szz_results}
    # Prepare comparison results
    comparison_results = []

    for cppcheck_entry in cppcheck_results:
        hash_introduced = cppcheck_entry['hash_introduced']

        # Check if this hash exists in V-SZZ data
        vszz_entry = vszz_index.get(hash_introduced)
        if vszz_entry:
            # Compare vulnerabilities
            cppcheck_vulns = cppcheck_entry.get('vulnerabilities', {})
            vszz_vuln_pattern = vszz_entry['bug_pattern']
            vszz_severity = vszz_entry.get('severity', 'N/A')

            # Create a result entry with comparison details
            comparison_results.append({
                'hash_introduced': hash_introduced,
                'cppcheck_vulnerabilities': cppcheck_vulns,
                'vszz_bug_pattern': vszz_vuln_pattern,
                'vszz_severity': vszz_severity,
                'cppcheck_vuln_time': cppcheck_entry['vulnerable_time'],
                'vszz_vuln_time': vszz_entry['vulnerable_time'],
                'matches': True if vszz_vuln_pattern is not None else False
            })
        else:
            # No match found in V-SZZ
            comparison_results.append({
                'hash_introduced': hash_introduced,
                'cppcheck_vulnerabilities': cppcheck_entry.get('vulnerabilities', {}),
                'vszz_bug_pattern': None,
                'vszz_severity': None,
                'cppcheck_vuln_time': cppcheck_entry['vulnerable_time'],
                'vszz_vuln_time': None,
                'matches': False
            })

    return comparison_results


def print_statistics(comparison_results):
    total_cppcheck_vulns = 0
    total_vszz_vulns = 0
    matching_vulns = 0
    unique_cppcheck_vulns = 0
    unique_vszz_vulns = 0
    severity_distribution = defaultdict(int)
    time_differences = []

    for result in comparison_results:
        # Count vulnerabilities detected by `cppcheck`
        cppcheck_vulns = result['cppcheck_vulnerabilities']
        vszz_pattern = result['vszz_bug_pattern']
        vszz_severity = result['vszz_severity']
        matches = result['matches']

        # Total counts
        total_cppcheck_vulns += len(cppcheck_vulns)
        total_vszz_vulns += 1 if vszz_pattern else 0

        # Matching and unique counts
        if matches:
            matching_vulns += 1
            # Calculate time difference if both timestamps are available
            cppcheck_time = datetime.strptime(result['cppcheck_vuln_time'], '%Y-%m-%d %H:%M:%S')
            vszz_time = datetime.strptime(result['vszz_vuln_time'], '%Y-%m-%d %H:%M:%S')
            time_differences.append(abs((cppcheck_time - vszz_time).total_seconds()))
        else:
            if cppcheck_vulns and not vszz_pattern:
                unique_cppcheck_vulns += 1
            if vszz_pattern and not cppcheck_vulns:
                unique_vszz_vulns += 1

        # Count severity distribution
        if vszz_severity:
            severity_distribution[vszz_severity] += 1

    # Calculate average time difference if there are matches
    avg_time_diff = sum(time_differences) / len(time_differences) if time_differences else 0
    avg_time_diff_hours = avg_time_diff / 3600  # Convert seconds to hours

    # Print the statistics
    print("Vulnerability Comparison Statistics:")
    print(f"Total Vulnerabilities Detected by cppcheck: {total_cppcheck_vulns}")
    print(f"Total Vulnerabilities Detected by V-SZZ: {total_vszz_vulns}")
    print(f"Matching Vulnerabilities (Detected by Both): {matching_vulns}")
    print(f"Unique Vulnerabilities Detected Only by cppcheck: {unique_cppcheck_vulns}")
    print(f"Unique Vulnerabilities Detected Only by V-SZZ: {unique_vszz_vulns}")
    print("\nSeverity Distribution in V-SZZ Detected Vulnerabilities:")
    for severity, count in severity_distribution.items():
        print(f"  {severity}: {count}")
    print(f"\nAverage Time Difference Between Matching Vulnerabilities: {avg_time_diff_hours:.2f} hours")


def visualize_statistics(comparison_results):
    # Initialize counters
    total_cppcheck_vulns = 0
    total_vszz_vulns = 0
    matching_vulns = 0
    unique_cppcheck_vulns = 0
    unique_vszz_vulns = 0
    severity_distribution = defaultdict(int)
    time_differences = []

    # Calculate statistics
    for result in comparison_results:
        cppcheck_vulns = result['cppcheck_vulnerabilities']
        vszz_pattern = result['vszz_bug_pattern']
        vszz_severity = result['vszz_severity']
        matches = result['matches']

        total_cppcheck_vulns += len(cppcheck_vulns)
        total_vszz_vulns += 1 if vszz_pattern else 0

        if matches:
            matching_vulns += 1
            cppcheck_time = datetime.strptime(result['cppcheck_vuln_time'], '%Y-%m-%d %H:%M:%S')
            vszz_time = datetime.strptime(result['vszz_vuln_time'], '%Y-%m-%d %H:%M:%S')
            time_differences.append(abs((cppcheck_time - vszz_time).total_seconds()) / 3600)  # Convert to hours
        else:
            if cppcheck_vulns and not vszz_pattern:
                unique_cppcheck_vulns += 1
            if vszz_pattern and not cppcheck_vulns:
                unique_vszz_vulns += 1

        if vszz_severity:
            severity_distribution[vszz_severity] += 1

    # Visualization 1: Bar chart for total and unique vulnerabilities
    labels = ['cppcheck Total', 'V-SZZ Total', 'Unique to cppcheck', 'Unique to V-SZZ', 'Matching']
    values = [total_cppcheck_vulns, total_vszz_vulns, unique_cppcheck_vulns, unique_vszz_vulns, matching_vulns]

    plt.figure(figsize=(10, 6))
    plt.bar(labels, values, color=['skyblue', 'orange', 'green', 'red', 'purple'])
    plt.title('Vulnerability Detection Comparison')
    plt.ylabel('Count')
    plt.show()

    # Visualization 2: Pie chart for severity distribution
    severity_labels = list(severity_distribution.keys())
    severity_counts = list(severity_distribution.values())

    plt.figure(figsize=(8, 8))
    plt.pie(severity_counts, labels=severity_labels, autopct='%1.1f%%', startangle=140)
    plt.title('Severity Distribution of V-SZZ Vulnerabilities')
    plt.show()

    # Visualization 3: Histogram for time differences between matching vulnerabilities
    if time_differences:
        plt.figure(figsize=(10, 6))
        plt.hist(time_differences, bins=10, color='teal', edgecolor='black')
        plt.title('Time Difference Between Matching Vulnerabilities')
        plt.xlabel('Time Difference (hours)')
        plt.ylabel('Frequency')
        plt.show()
    else:
        print("No matching vulnerabilities found for time difference analysis.")


def export_data(project_name):
    # Step 1: load all commits information
    commits_info = data_control.load_json(project_name, process_type="commits")
    # Step 2: load commits_introduce_vulnerable traditional version
    commits_introduce_vulnerable_traditional = data_control.load_json(project_name,
                                                                      process_type="commits_introduce_vulnerabilities_traditional")
    # Step 3: load commits_introduce_vulnerable advanced version
    commits_introduce_vulnerable_advanced = data_control.load_json(project_name,
                                                                   process_type="commits_introduce_vulnerabilities_advanced")
    # Step 4: load commit_labels_cppcheck
    commit_labels_cppcheck = data_control.load_json(project_name, process_type="commit_labels_cppcheck")
    # Step 5: Initialize results dictionary
    results = {}
    for commit in commits_info:
        results[commit["hash"]] = {
            "commit_time": commit["commit_time"],
            "files": commit.get("files", []),
            "has_files": bool(commit.get("files")),
            "traditional_vszz_label": 0,
            "advanced_vszz_label": 0,
            "cppcheck_label": 0,
            "vulnerability_pattern": None,
            "vulnerability_severity": None
        }

    # Step 6: Update traditional_vszz_label
    for entry in commits_introduce_vulnerable_traditional:
        commit_hash = entry["hash_introduced"]
        if commit_hash in results:
            results[commit_hash]["traditional_vszz_label"] = 1
            results[commit_hash]["vulnerability_pattern"] = entry["bug_pattern"]
            results[commit_hash]["vulnerability_severity"] = entry["severity"]

    # Step 7: Update advanced_vszz_label
    for entry in commits_introduce_vulnerable_advanced:
        commit_hash = entry["hash_introduced"]
        if commit_hash in results:
            results[commit_hash]["advanced_vszz_label"] = 1
            results[commit_hash]["vulnerability_pattern"] = entry["bug_pattern"]
            results[commit_hash]["vulnerability_severity"] = entry["severity"]

    # Step 8: Update cppcheck_label
    for entry in commit_labels_cppcheck:
        commit_hash = entry["hash_introduced"]
        if commit_hash in results:
            results[commit_hash]["cppcheck_label"] = 1
            results[commit_hash]["vulnerability_pattern"] = "Cppcheck"
            results[commit_hash]["vulnerability_severity"] = "Unknown"

    # Step 9: Export results to json file
    data_control.save_to_json(project_name, results, process_type="final_data")
    # export results to pandas dataframe that can be used for machine learning

    df = pd.DataFrame(results).T
    df.reset_index(inplace=True)
    df.rename(columns={"index": "commit_hash"}, inplace=True)

    # Save to CSV
    df.to_csv(f"./data/{project_name}/{project_name}_dataframe.csv", index=False, header=True)
    print(f"Data exported successfully to {project_name}_dataframe.csv")


def start_process():
    szz_versions = ["advanced", "traditional"]
    print("Fetching vulnerabilities...")
    cve_data = data_control.load_json(project_name, process_type="vulnerabilities")
    # check if the vulnerability information is already saved
    if not cve_data:
        log.error("Vulnerabilities not found in the database")
        log.error("Fetching vulnerabilities from api database...")
        print("Loading vulnerabilities from api database...")
        fetcher = VulnerabilityFetcher(project_name, api_key=api_key, severity=severity)
        cve_data = fetcher.fetch_all()
        data_control.save_to_json(project_name, cve_data, process_type="vulnerabilities")

    print("Vulnerabilities fetched successfully")
    log.info("Vulnerabilities fetched successfully")
    # check if the commits information is already saved
    print("Loading commits information...")
    log.info("Loading commits information...")
    # Initialize commits_info as an empty list by default
    commits_info = data_control.load_json(project_name, process_type="commits")
    log.info("Commits information loaded successfully")

    # Check if commit_info exists and contains data
    if not commits_info:
        print(f"Processing commit information from repository {code_repository_path}...")
        log.info(f"Processing commit information from repository {code_repository_path}...")
        loader = CommitLoader(code_repository_path, branch=repository_branch)
        commits_info = loader.load_commits(test_mode=False)
        data_control.save_to_json(project_name, commits_info, process_type="commits")
    else:
        print("Commits information loaded successfully")

    for szz_version in szz_versions:
        linked_commits = data_control.load_json(project_name, process_type=f"linked_commits_{szz_version}")
        if not linked_commits:
            print("Starting commit analysis...")
            log.info("Starting commit analysis...")
            start_time = time.time()
            analyzer = CommitAnalyzer(cve_data, sem_threshold=0.75, syn_threshold=0.05, Debug=False,
                                      version=szz_version)
            linked_commits = analyzer.analyze_commits(commits_info, num_workers=num_workers)
            end_time = time.time()
            log.info(
                f"Commit analysis completed in {(end_time - start_time):.5f} seconds, using {num_workers} workers.")
            print(f"Commit analysis completed in {(end_time - start_time):.5f} seconds, using {num_workers} workers.")
            data_control.save_to_json(project_name, linked_commits, process_type=f"linked_commits_{szz_version}")
        else:
            print(f"Linked commits version {szz_version} loaded successfully")

        commits_introduce_vulnerable = data_control.load_json(project_name,
                                                              process_type=f"commits_introduce_vulnerabilities_{szz_version}")
        if not commits_introduce_vulnerable:
            labeler = CommitLabeler(project_name, repo_url, commits_info, linked_commits)
            commits_introduce_vulnerable = labeler.label_data_szz()
            data_control.save_to_json(project_name, commits_introduce_vulnerable,
                                      process_type=f"commits_introduce_vulnerabilities_{szz_version}")
            log.info("Process completed successfully")
            print("Process completed successfully")
            print_vulnerability_statistics(commits_introduce_vulnerable)
    print("------------------------------------------------------")

    commit_labels_cppcheck = data_control.load_json(project_name, process_type="commit_labels_cppcheck")
    if not commit_labels_cppcheck:
        print("Starting cppcheck commit analysis...")
        log.info("Starting cppcheck commit analysis...")
        start_time = time.time()
        repository = GitRepository(repo_path=code_repository_path, branch_name=repository_branch)
        scanner = VulnerabilityScanner(repo_path=code_repository_path, file_ext_to_parse=['cpp', 'c', 'h', 'hpp'])
        processor = CommitProcessor(repository=repository, scanner=scanner)
        processor.process_all_commits()
        end_time = time.time()
        log.info(f"Cppcheck commit analysis completed in {(end_time - start_time):.5f} seconds.")
        print(f"Cppcheck commit analysis completed in {(end_time - start_time):.5f} seconds.")
        commit_labels_cppcheck = processor.commit_labels
        data_control.save_to_json(project_name, commit_labels_cppcheck, process_type="commit_labels_cppcheck")
        print("------------------------------------------------------")

    print(f"All data loaded successfully for project {project_name}")
    export_data(project_name)

    # Initialize the VulnerabilityAnalyzer with file paths
    analyzer = VulnerabilityAnalyzer(project_name=project_name, data_control=data_control)

    # Generate a report based on the analysis
    analyzer.calculate_confusion_matrix_metrics(f"./data/{project_name}/{project_name}_confusion_matrix_metrics.csv")


def verify_nvd_api():
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    headers = {"apiKey": api_key}
    params = {
        'keywordSearch': project_name,
        'resultsPerPage': 1,
        'startIndex': 0
    }
    try:
        response = requests.get(url, headers=headers, params=params)
        if response.status_code == 200:
            print("NVD API key is valid.")
        else:
            print(f"Failed to verify NVD API key. Status code: {response.status_code}")
    except requests.exceptions.RequestException as e:
        print(f"Error verifying NVD API key: {e}")


def main():
    """
    Main entry point for the VISTA tool. Provides command-line arguments for project analysis and API verification.
    """
    # Create the argument parser
    parser = argparse.ArgumentParser(
        description="VISTA: Vulnerability Identification and Software Tracking Analyzer"
    )

    # Add CLI arguments
    parser.add_argument(
        "--project",
        type=str,
        help="The name of the project to analyze. This should match the folder name in the `data/` directory.",
    )
    parser.add_argument(
        "--verify-api",
        action="store_true",
        help="Verify the NVD API key in the configuration.",
    )

    # Parse the arguments
    args = parser.parse_args()

    # Default behavior if no arguments are provided
    if not args.project and not args.verify_api:
        print(f"Starting analysis for project: {project_name}")
        log.info(f"Starting default analysis for project: {project_name}")
        start_process()
    # If `--verify-api` is used
    elif args.verify_api:
        log.info("Verifying NVD API key...")
        if nvd_api_key == "ADD_YOUR_NVD_API_KEY":
            log.error("API key not set in the configuration. Please update `config.json`.")
            print("Error: API key not set. Please update the `nvd_api_key` field in `config.json`.")
        else:
            verify_nvd_api()


if __name__ == "__main__":
    main()
