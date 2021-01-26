## Comments

This demo is divided in 3 options ( client side encryption ) :
- Option 1: Using a CMK stored in AWS KMS
- Option 2: Using a CMK stored in AWS KMS & Using AWS KMS encrypt-decrypt operation
- ption 3: Using AWS Encryption SDK is a client-side encryption library designed

## Prerequisites create virtual Env

python3 -m venv env
source env/bin/activate
pip install --upgrade pip
pip install boto3 aws-encryption-sdk pycryptodome 

## Create KMS Symmetric CMK

aws kms create-key \
    --tags TagKey=Purpose,TagValue=Test \
    --description "Development test key" 

## Update the CMK ARN

into main.py search for MASTER_KEY_ARN and update it.

## links
boto3 KMS :  https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/kms.html
cli KMS: https://docs.aws.amazon.com/cli/latest/reference/kms/index.html
AWS encryption SDK : https://pypi.org/project/aws-encryption-sdk/
AWS encryption SDK AWS DOc : https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/introduction.html

