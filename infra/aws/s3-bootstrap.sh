#!/usr/bin/env bash
set -euo pipefail

# Run this from an authenticated AWS CLI session.
# Example: AWS_PROFILE=your-profile ./s3-bootstrap.sh

: "${AWS_REGION:=ap-south-1}"
: "${BUCKET_NAME:?Set BUCKET_NAME to a globally unique S3 bucket name}"
: "${KEY_ALIAS:=alias/couple-vault-production}"

ACCOUNT_ID="$(aws sts get-caller-identity --query Account --output text)"

if ! aws kms describe-key --key-id "$KEY_ALIAS" >/dev/null 2>&1; then
  KEY_ID="$(aws kms create-key --description 'Couple Vault S3 encryption key' --enable-key-rotation --query KeyMetadata.KeyId --output text)"
  aws kms create-alias --alias-name "$KEY_ALIAS" --target-key-id "$KEY_ID"
else
  KEY_ID="$(aws kms describe-key --key-id "$KEY_ALIAS" --query KeyMetadata.KeyId --output text)"
fi

echo "KMS key: $KEY_ID"

if ! aws s3api head-bucket --bucket "$BUCKET_NAME" 2>/dev/null; then
  aws s3api create-bucket \
    --bucket "$BUCKET_NAME" \
    --region "$AWS_REGION" \
    --create-bucket-configuration LocationConstraint="$AWS_REGION"
fi

aws s3api put-public-access-block --bucket "$BUCKET_NAME" --public-access-block-configuration \
  BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true

aws s3api put-bucket-ownership-controls --bucket "$BUCKET_NAME" --ownership-controls 'Rules=[{ObjectOwnership=BucketOwnerEnforced}]'

aws s3api put-bucket-versioning --bucket "$BUCKET_NAME" --versioning-configuration Status=Enabled

aws s3api put-bucket-encryption --bucket "$BUCKET_NAME" --server-side-encryption-configuration \
  "Rules=[{ApplyServerSideEncryptionByDefault={SSEAlgorithm=aws:kms,KMSMasterKeyID=arn:aws:kms:${AWS_REGION}:${ACCOUNT_ID}:key/${KEY_ID}},BucketKeyEnabled=true}]"

cat > /tmp/couple-vault-bucket-policy.json <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyInsecureTransport",
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:*",
      "Resource": [
        "arn:aws:s3:::${BUCKET_NAME}",
        "arn:aws:s3:::${BUCKET_NAME}/*"
      ],
      "Condition": {"Bool": {"aws:SecureTransport": "false"}}
    }
  ]
}
POLICY
aws s3api put-bucket-policy --bucket "$BUCKET_NAME" --policy file:///tmp/couple-vault-bucket-policy.json

cat <<INFO

S3 is configured.

Bucket: $BUCKET_NAME
Region: $AWS_REGION
KMS alias: $KEY_ALIAS
KMS key id: $KEY_ID

Next:
1. Give ONLY your backend runtime IAM role access to this bucket.
2. Give that role s3:GetObject/s3:PutObject/s3:DeleteObject on arn:aws:s3:::$BUCKET_NAME/vaults/*.
3. Give the role kms:Encrypt/kms:Decrypt/kms:GenerateDataKey on this KMS key.
4. Never put AWS access keys in frontend code or VITE_* variables.
INFO
