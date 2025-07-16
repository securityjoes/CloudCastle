import boto3
import json
import os
import sys
from botocore.exceptions import ClientError, NoCredentialsError

AUDIT_ROLE_NAME = "CloudcastleCrossAccountRole"

CONFIG_FILE = os.path.join(os.path.dirname(__file__), "..", "utils", "cloudcastle_config.json")


def load_aws_config():
    if not os.path.exists(CONFIG_FILE):
        return {}
    with open(CONFIG_FILE, "r") as f:
        return json.load(f)



def show_aws_auth_status():
    try:
        session = boto3.Session()
        sts = session.client("sts")
        status = "✅" if sts.get_caller_identity() else "❌"
        print(f"[{status}] AWS")
    except NoCredentialsError:
        print(" ❌ AWS credentials not configured or default profile is empty.")
        print("    Check the default profile on .aws/credentials or")
        print("    Run `aws configure` and setup the access key and secret key as default:")
        sys.exit(1) 
    except ClientError as e:
       print(f"❌ AWS error: {e}")
       sys.exit(1) 


def assume_role(account_id):
    role_arn = f"arn:aws:iam::{account_id}:role/{AUDIT_ROLE_NAME}"
    sts_client = boto3.client("sts")
    try:
        response = sts_client.assume_role(
            RoleArn=role_arn,
            RoleSessionName="CloudCastleSession"
        )
        creds = response["Credentials"]
        session = boto3.Session(
            aws_access_key_id=creds["AccessKeyId"],
            aws_secret_access_key=creds["SecretAccessKey"],
            aws_session_token=creds["SessionToken"]
        )
        return session
    except ClientError as e:
        # print(f"❌ Could not assume role in account {account_id}: {e}")
        return None

def list_aws_accounts():

    try:
        config = load_aws_config()
        if not config:
            print("⚠️ No AWS account config found.")
            return []  # ✅ ensure fallback

        accounts = []
        for acct in config:
            account_id = acct["id"]
            account_name = acct.get("name", account_id)

            session = assume_role(account_id)
            status = "✅" if session else "❌"

            accounts.append({
                "id": account_id,
                "name": account_name,
                "status": status,
                "session": session
            })

        return accounts
    except Exception as e:
        print(f"❌ Failed to load AWS accounts: {e}")
        return []  # ✅ ensure always returns a list
