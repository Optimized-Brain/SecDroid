import os
import re
import json
import logging

class CustomRuleEngine:
    """
    A custom rule engine that loads user–defined rules from a JSON file.
    Each rule is expected to have:
      - 'description': A brief description of what the rule checks.
      - 'pattern': A regular expression pattern to search for.
      - 'severity': A label for the rule's impact (e.g., Low, Medium, High).
      - (Optional) 'file_types': A list of file extensions (e.g., ".java", ".xml") to which the rule applies.
    """
    def __init__(self, rules_file):
        self.rules = []
        self.load_rules(rules_file)

    def load_rules(self, rules_file):
        """
        Loads the custom rules from the specified JSON file.
        """
        try:
            with open(rules_file, "r", encoding="utf-8") as f:
                self.rules = json.load(f)
            logging.info(f"Loaded {len(self.rules)} custom rules from {rules_file}")
        except Exception as e:
            logging.error(f"Error loading rules from {rules_file}: {e}")

    def scan_file(self, file_path):
        """
        Scans a single file against all loaded rules.
        Returns a list of findings where each finding is a dictionary.
        """
        findings = []
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
        except Exception as e:
            logging.error(f"Error reading file {file_path}: {e}")
            return findings

        for rule in self.rules:
            # If the rule defines applicable file types, check if current file qualifies.
            if "file_types" in rule:
                ext = os.path.splitext(file_path)[1]
                if ext not in rule["file_types"]:
                    continue

            pattern = rule.get("pattern")
            if not pattern:
                continue

            try:
                regex = re.compile(pattern, re.MULTILINE)
            except re.error as e:
                logging.error(f"Invalid regex pattern '{pattern}' in rule '{rule.get('description', '')}': {e}")
                continue

            for match in regex.finditer(content):
                # Calculate line number by counting newline characters before match
                line_num = content[:match.start()].count("\n") + 1
                findings.append({
                    "file": file_path,
                    "rule_description": rule.get("description", "No description provided"),
                    "severity": rule.get("severity", "Unknown"),
                    "match": match.group(),
                    "line": line_num
                })
        return findings

    def scan_directory(self, directory):
        """
        Recursively scans a directory for files and applies the rule engine on each file.
        Returns a list of all findings.
        """
        all_findings = []
        for root, dirs, files in os.walk(directory):
            for file in files:
                file_path = os.path.join(root, file)
                file_findings = self.scan_file(file_path)
                if file_findings:
                    all_findings.extend(file_findings)
        return all_findings

if __name__ == "__main__":
    import argparse

    # Setup argument parser for command-line usage
    parser = argparse.ArgumentParser(
        description="Custom Rule Engine for SecDroid - Scan files for security rule violations"
    )
    parser.add_argument("-r", "--rules", required=True,
                        help="Path to the custom rules JSON file")
    parser.add_argument("-d", "--directory", required=True,
                        help="Directory to scan for custom rule violations")
    args = parser.parse_args()

    # Setup logging
    logging.basicConfig(level=logging.INFO, format="%(message)s")

    # Instantiate the custom rule engine and scan the directory
    engine = CustomRuleEngine(args.rules)
    results = engine.scan_directory(args.directory)

    # Output the findings
    if results:
        for finding in results:
            logging.info(f"[{finding['severity']}] {finding['file']}:{finding['line']} - {finding['rule_description']}")
            logging.info(f"    Matched text: {finding['match']}\n")
    else:
        logging.info("No rule violations found.")
