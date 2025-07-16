## Requirements

- Python 3.11+
- Python modules listed on /requirements.txt
- AWS CLI (configured on your local machine)
- Access to multiple AWS accounts (Cloud Castle Main Account + Target accounts)

## Step 1: Create an IAM User (Cloud Castle Main Account)

Let's assumed the AWS account on where you will create the IAM user as `Cloud Castle Main Account`.

This IAM user will serve as the identity that assumes roles in other AWS accounts.

1. Sign in to the Cloud Castle Main AWS account.

2. Navigate to IAM > Users, then click Create user.

3. Name the user: `cloudcastle-auditor`

4. Select Programmatic access.

5. Attach the following policies:

- SecurityAudit (AWS-managed policy)
- ViewOnlyAccess (AWS-managed policy)
- Custom inline policy for sts:AssumeRole:

```
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "sts:AssumeRole",
      "Resource":  [
        "arn:aws:iam::<Cloud_Castle_Main_ACCOUNT_ID>:role/CloudcastleCrossAccountRole",
        "arn:aws:iam::<cloud_castle1_account_id>:role/CloudcastleCrossAccountRole"
        ]
    }
  ]
}
```

_If you are planning to scan multiple accounts, add each role ARN inside the resource block. Make sure to also include the `Cloud Castle Main account` on resource block._
_Replace <Cloud_Castle_Main_ACCOUNT_ID> with the 12-digit AWS account ID where your IAM user resides and the <cloud_castle1_account_id> with the other AWS account ID that you want to include in the scan._

6. Complete user creation and download the access key and secret key.

7. Configure the AWS credential on your machine via AWS CLI: `aws configure`

_Note:_ _The tool will use the "default" profile from the AWS credentials. Make sure that you put the access key and secret key under the default AWS profile._

## Step 2: Create a Cross-Account Role in Target AWS Accounts

Each AWS account that you want to scan must include a role that this tool can assume. This is also required in the Cloud Castle Main Account.

1. Sign in to each target AWS account.

2. Go to IAM > Roles, then click Create role.

3. Select Custom Trust Policy and input the trust policy below. If you are creating the role for the Cloud Castle Main Account choose the option 'This account (aws_acount_id)'.

```
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::<Cloud_Castle_Main_ACCOUNT_ID>:user/cloudcastle-auditor"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
```

_Replace <Cloud_Castle_Main_ACCOUNT_ID> with the 12-digit AWS account ID where your IAM user resides. _

4. Proceed and attach these policies:

- SecurityAudit (AWS-managed policy)
- ViewOnlyAccess (AWS-managed policy)

5. Name the role: `CloudcastleCrossAccountRole`

6. Complete role creation.

_Note:_ _Use only the `CloudcastleCrossAccountRole` role name. Other role names will not be recognized by the tools._

## Step 3: Create the AWS Account Configuration File in CloudCastle

The tool reads a list of target AWS accounts from a local JSON file.

`utils/cloudcastle_config.json`

Sample Content:

```
[
    {
        "id": "111111111111",
        "name": "cloud_main_account"
    },
    {
        "id": "222222222222",
        "name": "cloud_castle_1"
}
]
```

_Note:_ _Replace the `"id":` with the AWS account ID that you want to scan and the `"name":` with the AWS account name or identifier for the AWS account._

## Step 3: Install Python Dependencies and Run the Tool

1. Make sure the required python modules are already installed:

```
pyfiglet
requests
Jinja2
boto3
typer
```

2. From your project root, execute:

`python cloudcastle.py`

You should see output like:

![image](https://github.com/user-attachments/assets/c7d6ae68-2dd1-4270-a7d9-67bffd65ec3e)

Each account will show a status indicating whether the role assumption was successful.
