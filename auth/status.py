import boto3
from botocore.exceptions import ClientError
from auth.auth_aws import show_aws_auth_status
from auth.auth_azure import show_azure_auth_status
from auth.auth_gcp import show_gcp_auth_status

def get_auth_status():
    return {
        "AWS": show_aws_auth_status(),
        "Azure": show_azure_auth_status(),
        "GCP": show_gcp_auth_status()
    }