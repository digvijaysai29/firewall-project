import json
import os

RULES_FILE = 'firewall/rules/rules.json'

def load_rules():
    """Load firewall rules from a JSON file."""
    if not os.path.exists(RULES_FILE):
        return []
    with open(RULES_FILE, 'r') as f:
        return json.load(f)

def save_rules(rules):
    """Save firewall rules to a JSON file."""
    with open(RULES_FILE, 'w') as f:
        json.dump(rules, f)

def add_rule(rule):
    """Add a new rule to the firewall."""
    rules = load_rules()
    rules.append(rule)
    save_rules(rules)

def remove_rule(rule):
    """Remove an existing rule from the firewall."""
    rules = load_rules()
    if rule in rules:
        rules.remove(rule)
        save_rules(rules)

if __name__ == "__main__":
    # Example of adding a rule
    add_rule({"ip": "192.168.1.100", "action": "block"})