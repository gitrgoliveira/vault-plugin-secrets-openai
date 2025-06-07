#!/bin/bash
# delete_all_service_accounts.sh
# Deletes all service accounts for a given OpenAI project using the OpenAI API.

# Check required environment variables
if [ -z "$OPENAI_ADMIN_API_KEY" ] || [ -z "$OPENAI_ORG_ID" ] || [ -z "$OPENAI_PROJECT_ID" ]; then
  echo "❌ ERROR: Please set OPENAI_ADMIN_API_KEY, OPENAI_ORG_ID, and OPENAI_PROJECT_ID environment variables."
  exit 1
fi

API_URL="https://api.openai.com/v1/organization/projects/$OPENAI_PROJECT_ID/service_accounts"

# List all service accounts
SERVICE_ACCOUNTS=$(curl -s -H "Authorization: Bearer $OPENAI_ADMIN_API_KEY" \
  -H "OpenAI-Organization: $OPENAI_ORG_ID" \
  "$API_URL" | jq -r '.data[].id')

if [ -z "$SERVICE_ACCOUNTS" ]; then
  echo "No service accounts found for project $OPENAI_PROJECT_ID."
  exit 0
fi

echo "Deleting the following service accounts:"
echo "$SERVICE_ACCOUNTS"

for SA_ID in $SERVICE_ACCOUNTS; do
  echo "Deleting service account: $SA_ID"
  curl -s -X DELETE -H "Authorization: Bearer $OPENAI_ADMIN_API_KEY" \
    -H "OpenAI-Organization: $OPENAI_ORG_ID" \
    "$API_URL/$SA_ID"
done

echo "✅ All service accounts deleted for project $OPENAI_PROJECT_ID."
