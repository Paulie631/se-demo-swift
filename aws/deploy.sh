#!/usr/bin/env bash
# Deploy / tear down the Amazon Quick demo environment.
#   ./deploy.sh                       # core only (data bucket + MCP server)
#   ZPA_KEY=... AMI=ami-... ./deploy.sh --zpa      # + VPC, Quick PrivateLink, App Connector
#   ./deploy.sh --delete
# Env: AWS_REGION (default us-east-1, a Quick launch region), STACK (default zs-quick-demo),
#      MCP_TOKEN (optional bearer token for the MCP server), KEYPAIR (optional).
set -euo pipefail
cd "$(dirname "$0")"
REGION="${AWS_REGION:-us-east-1}"
STACK="${STACK:-zs-quick-demo}"

if [[ "${1:-}" == "--delete" ]]; then
  aws cloudformation delete-stack --stack-name "$STACK" --region "$REGION"
  echo "Deleting $STACK (the bucket is emptied automatically)..."
  aws cloudformation wait stack-delete-complete --stack-name "$STACK" --region "$REGION"
  echo "Deleted."; exit 0
fi

PARAMS=(ProjectName="$STACK" McpToken="${MCP_TOKEN:-}")
if [[ "${1:-}" == "--zpa" ]]; then
  : "${ZPA_KEY:?set ZPA_KEY to the App Connector provisioning key}"
  : "${AMI:?set AMI to the Zscaler App Connector AMI ID for $REGION}"
  PARAMS+=(EnableZpaPath=true ZpaProvisioningKey="$ZPA_KEY" AppConnectorAmiId="$AMI" KeyPairName="${KEYPAIR:-}")
fi

[[ -f quick-demo-env.yaml ]] || python3 build.py
aws cloudformation deploy \
  --region "$REGION" --stack-name "$STACK" \
  --template-file quick-demo-env.yaml \
  --capabilities CAPABILITY_IAM \
  --parameter-overrides "${PARAMS[@]}"

aws cloudformation describe-stacks --stack-name "$STACK" --region "$REGION" \
  --query 'Stacks[0].Outputs[].[OutputKey,OutputValue]' --output table
