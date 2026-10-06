import os
from dotenv import load_dotenv
import mysql.connector

# Load environment variables from .env
load_dotenv()

# =========================
# MySQL Connection
# =========================

db = mysql.connector.connect(
    host="localhost",
    user="cis_app",
    password=os.getenv("CIS_DB_PASSWORD"),
    database="CIS_DB"
)

print("Connected to CIS_DB successfully!\n")

cursor = db.cursor()

# =========================
# Get Active CIS Rules
# =========================

cursor.execute("""
    SELECT
        rule_id,
        cis_id,
        title,
        platform
    FROM cis_rules
    WHERE is_active = TRUE
    ORDER BY rule_id
""")

rules = cursor.fetchall()

# =========================
# Display Rules and Commands
# =========================

print("========================================")
print("          CIS SECURITY AUDIT")
print("========================================")

for rule in rules:

    rule_id = rule[0]
    cis_id = rule[1]
    title = rule[2]
    platform = rule[3]

    print("\n----------------------------------------")
    print(f"CIS ID    : {cis_id}")
    print(f"Title     : {title}")
    print(f"Platform  : {platform}")
    print("----------------------------------------")

    # Get commands belonging to this rule
    cursor.execute("""
        SELECT
            command_id,
            command_type,
            step_order,
            command,
            description,
            expected_result,
            match_type,
            timeout_seconds,
            requires_root,
            shell
        FROM cis_commands
        WHERE rule_id = %s
        ORDER BY command_type, step_order
    """, (rule_id,))

    commands = cursor.fetchall()

    if not commands:
        print("No commands found for this rule.")
        continue

    for cmd in commands:

        command_id = cmd[0]
        command_type = cmd[1]
        step_order = cmd[2]
        command = cmd[3]
        description = cmd[4]
        expected_result = cmd[5]
        match_type = cmd[6]
        timeout_seconds = cmd[7]
        requires_root = cmd[8]
        shell = cmd[9]

        print(f"\nCommand ID       : {command_id}")
        print(f"Command Type     : {command_type}")
        print(f"Step Order       : {step_order}")
        print(f"Command          : {command}")

        if description:
            print(f"Description      : {description}")

        if expected_result:
            print(f"Expected Result  : {expected_result}")

        if match_type:
            print(f"Match Type       : {match_type}")

        print(f"Timeout          : {timeout_seconds} seconds")
        print(f"Requires Root    : {requires_root}")

        if shell:
            print(f"Shell            : {shell}")

# =========================
# Close Database
# =========================

cursor.close()
db.close()

print("\n========================================")
print("Database connection closed.")
print("========================================")