##  Copyright 2023 Google LLC
##  
##  Licensed under the Apache License, Version 2.0 (the "License");
##  you may not use this file except in compliance with the License.
##  You may obtain a copy of the License at
##  
##      https://www.apache.org/licenses/LICENSE-2.0
##  
##  Unless required by applicable law or agreed to in writing, software
##  distributed under the License is distributed on an "AS IS" BASIS,
##  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
##  See the License for the specific language governing permissions and
##  limitations under the License.


##  This code creates demo environment for CSA - Application Development Architecture Pattern   ##
##  This demo code is not built for production workload ##

#!/bin/bash

set -e  # Exit the script on any error

# User configuration selection
echo "Choose configuration method:"
echo "1. Use a simple configuration based on the project ID"
echo "2. Supply your own configuration file path"

read -p "Enter your choice (1 or 2): " choice

# Configuration logic based on user choice
if [[ $choice == "1" ]]; then
    echo "Creating sample configuration."

    # Get user input for project ID and region (already in your script)
    read -p "Enter your Google Cloud Project ID: " PROJECT_ID

    # Validate project ID (optional)
    if [[ -z "$PROJECT_ID" ]]; then
    echo "Error: Please enter a project ID."
    exit 1
    fi

    read -p "Enter the Google Cloud Region (e.g., us-central1): " LOCATION

    # Validate region (optional)
    if [[ -z "$LOCATION" ]]; then
    echo "Error: Please enter a region."
    exit 1
    fi

    # Generate UUID
    UUID=$(cat /dev/urandom | tr -dc '0-9' | fold -w 10 | head -n 1)

    # Set other variables based on project ID
    KEY_NAME="${PROJECT_ID}-key"
    KEYRING_NAME="${PROJECT_ID}-keyring"
    INPUTFILE_NAME="provision/inputfile.json"
    TEMPLATE_NAME="sensitive_data_inspection"

    # Set environment variables
    export PROJECT_ID=$PROJECT_ID
    export LOCATION=$LOCATION
    export INPUT_BUCKET="${PROJECT_ID}-${UUID}-input-bucket"
    export LOGGING_BUCKET="${PROJECT_ID}-${UUID}-logging-bucket"
    export WRAPPEDKEY_BUCKET="${PROJECT_ID}-${UUID}-key-bucket"
    export KEY_NAME="${PROJECT_ID}-key"
    export KEYRING_NAME="${PROJECT_ID}-keyring"
    export INPUTFILE_NAME="inputfile.json"
    export TEMPLATE_NAME="sensitive_data_inspection_${UUID}"

elif [[ $choice == "2" ]]; then
  config_file_path=$(get_user_input "Enter the path to your configuration file: ")
  if [[ ! -f "$config_file_path" ]]; then
    echo "Error: File not found or not accessible at '$config_file_path'."
    exit 1
  fi

  # Assuming config file sets variables using assignment (source or individual lines)
  source "$config_file_path"  # Optional: Source the config file if it sets variables directly

else
  echo "Invalid choice. Please select 1 or 2."
  exit 1
fi

# Derived variables based on environment variables
KEY_PATH="projects/${PROJECT_ID}/locations/global/keyRings/${KEYRING_NAME}/cryptoKeys/${KEY_NAME}"
INSPECT_TEMPLATE_PATH="projects/${PROJECT_ID}/inspectTemplates/${TEMPLATE_NAME}"

# Install dependencies
echo "Installing dependencies..."
pip3 install -r provision/requirements.txt

# Run the setup script
echo "Running LLM logging setup..."
python provision/llm-log-setup.py \
  --PROJECT_ID="$PROJECT_ID" \
  --LOCATION="$LOCATION" \
  --INPUT_BUCKET="$INPUT_BUCKET" \
  --LOGGING_BUCKET="$LOGGING_BUCKET" \
  --WRAPPEDKEY_BUCKET="$WRAPPEDKEY_BUCKET" \
  --KEY_NAME="$KEY_NAME" \
  --KEYRING_NAME="$KEYRING_NAME" \
  --INPUTFILE_NAME="$INPUTFILE_NAME" \
  --TEMPLATE_NAME="$TEMPLATE_NAME"

echo "LLM logging setup complete!"

# Reminder for unauthenticated invocations
echo "**Reminder:** Allow unauthenticated invocations to [llm-logging] service for this demo."

# Deploy the service (capture output to file)
echo "Deploying service. This may take several minutes..."
gcloud run deploy llm-logging --allow-unauthenticated --source cloudrun --region $LOCATION --set-env-vars PROJECT_ID=$PROJECT_ID,LOCATION=$LOCATION,INPUT_BUCKET=$INPUT_BUCKET,LOGGING_BUCKET=$LOGGING_BUCKET,WRAPPEDKEY_BUCKET=$WRAPPEDKEY_BUCKET,KEY_NAME=$KEY_NAME,KEYRING_NAME=$KEYRING_NAME,INPUTFILE_NAME=$INPUTFILE_NAME,TEMPLATE_NAME=$TEMPLATE_NAME > output.txt 2>&1 &  # Run in the background and redirect

# Wait until specific output is seen
while true; do 
  if grep -q "Service URL:" output.txt; then break; fi  # Check if "Service URL:" is found 
  sleep 1 
done

# Extract service URL
service_url=$(cat output.txt | grep -o 'https://.*\.run\.app')

# Print testing instructions
echo "**To test the endpoint, copy and use this curl command. There will be no response, but you will see logs after the request completes:**"
echo " curl -H \"Authorization: Bearer \$(gcloud auth print-identity-token)\" $service_url"
echo "**Note:** Replace \$(gcloud auth print-identity-token) with your actual access token if needed."

# Print instructions for log viewing
echo "**View logs, visit this URL:**"
echo "console.cloud.google.com/logs/query;query=logName%3D\"projects%2F$PROJECT_ID%2Flogs%2Fllm-prompt\""

echo "or enter this query in Cloud Logging:"
echo "logName=\"projects/$PROJECT_ID/logs/llm-prompt\""

# Clean up temporary file
rm output.txt
