#!/usr/bin/env python3

# Copyright 2018 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# -*- coding: utf-8 -*-

from google import api_core
from google.cloud import storage, kms, dlp
from secrets import token_bytes
from base64 import b64encode
from typing import List, Optional

import uuid
import os
import json

# Set variables with env vars

# Access environment variables set by the Bash script
PROJECT_ID = os.environ.get("PROJECT_ID")
LOCATION = os.environ.get("LOCATION")
INPUT_BUCKET = os.environ.get("INPUT_BUCKET")
LOGGING_BUCKET = os.environ.get("LOGGING_BUCKET")
WRAPPEDKEY_BUCKET = os.environ.get("WRAPPEDKEY_BUCKET")
KEY_NAME = os.environ.get("KEY_NAME")
KEYRING_NAME = os.environ.get("KEYRING_NAME")
TEMPLATE_NAME = os.environ.get("TEMPLATE_NAME")

# ---- GCS Bucket Creation ----

storage_client = storage.Client()

def create_bucket(
    bucket_name: str, location: str
) -> storage.Bucket:

    try:
        bucket = storage_client.bucket(bucket_name)
        bucket.create(location=location)
        print(f"GCS bucket '{bucket_name}' created.")
    except api_core.exceptions.Conflict:
        print(f"Bucket '{bucket_name}' already exists. Skipping creation.")
    except Exception as e:
        print(f"Error creating bucket '{bucket_name}': {e}")
    finally:  # Always return the bucket, whether it was created or already existed
        return storage_client.bucket(bucket_name)

create_bucket(INPUT_BUCKET, LOCATION)
create_bucket(WRAPPEDKEY_BUCKET, LOCATION)
create_bucket(LOGGING_BUCKET, LOCATION)

# ---- Cloud KMS Key Generation & Encryption --->

# Key generation (implementation depends on your specific requirements)

# Encryption with Cloud KMS
print("Generating a data encryption key...")

# Key Creation
raw_keyset = token_bytes(32)

# KMS Client and Key Resource Path
kms_client = kms.KeyManagementServiceClient()

# Create Keyring (if it doesn't exist)
KEYRING_PATH = f"projects/{PROJECT_ID}/locations/global/keyRings/{KEYRING_NAME}"
try:
    kms_client.get_key_ring(name=KEYRING_PATH)
    print(f"Keyring '{KEYRING_NAME}' already exists.")
except api_core.exceptions.NotFound:
    kms_client.create_key_ring(
        parent=f"projects/{PROJECT_ID}/locations/global",
        key_ring_id=KEYRING_NAME,
    )
    print(f"Keyring '{KEYRING_NAME}' created.")
    
# Get Key Path
KEY_PATH = kms_client.crypto_key_path(PROJECT_ID, "global", KEYRING_NAME, KEY_NAME)

# Check Key Existence
try:
    kms_client.get_crypto_key(name=KEY_PATH)
    print(f"Key '{KEY_NAME}' already exists in keyring '{KEYRING_NAME}'.")
except api_core.exceptions.NotFound:
    # Create Key (if it doesn't exist)
    purpose = kms.CryptoKey.CryptoKeyPurpose.ENCRYPT_DECRYPT
    kms_client.create_crypto_key(
        parent=KEYRING_PATH,
        crypto_key_id=KEY_NAME,
        crypto_key={
            "purpose": purpose,
        },
    )
    print(f"Key '{KEY_NAME}' created in keyring '{KEYRING_NAME}'.")

# Key Wrapping
wrap_response = kms_client.encrypt(
    name=KEY_PATH,
    plaintext=raw_keyset,
)

raw_keyset_encrypted = wrap_response.ciphertext

wrapped_key = b64encode(raw_keyset_encrypted).decode()

# ---- Key Upload to Bucket ----

print("Copying wrapped DEK to " + WRAPPEDKEY_BUCKET)

bucket = storage_client.bucket(WRAPPEDKEY_BUCKET)
# keep 'assets/wrapped_key' hardcoded for consistency with cloudrun/main.py
blob = bucket.blob('assets/wrapped_key') 
blob.upload_from_string(wrapped_key)

print("Wrapped key uploaded to Cloud Storage successfully.")

# ---- Cloud DLP Inspect Template Creation ----
print("Creating Cloud DLP inspect template...")

def create_DLP_template(
    project: str,
    info_types: List[str],
    display_name: Optional[str] = None,
    template_id: Optional[str] = None,
    min_likelihood: Optional[int] = None,
    max_findings: Optional[int] = None,
    include_quote: Optional[bool] = None,
) -> None:
    """Creates a Data Loss Prevention API inspect template.
    Args:
        project: The Google Cloud project id to use as a parent resource.
        info_types: A list of strings representing info types to look for.
            A full list of info type categories can be fetched from the API.
        template_id: The id of the template. If omitted, an id will be randomly
            generated.
        display_name: The optional display name of the template.
        min_likelihood: A string representing the minimum likelihood threshold
            that constitutes a match. One of: 'LIKELIHOOD_UNSPECIFIED',
            'VERY_UNLIKELY', 'UNLIKELY', 'POSSIBLE', 'LIKELY', 'VERY_LIKELY'.
        max_findings: The maximum number of findings to report; 0 = no maximum.
        include_quote: Boolean for whether to display a quote of the detected
            information in the results.
    Returns:
        None; the response from the API is printed to the terminal.
    """

    # Instantiate a client.
    dlp_client = dlp.DlpServiceClient()

    # Prepare info_types by converting the list of strings into a list of
    # dictionaries (protos are also accepted).
    info_types = [{"name": info_type} for info_type in info_types]

    # Construct the configuration dictionary. Keys which are None may
    # optionally be omitted entirely.
    inspect_config = {
        "info_types": info_types,
        "min_likelihood": min_likelihood,
        "include_quote": include_quote,
        "limits": {"max_findings_per_request": max_findings},
    }

    inspect_template = {
        "inspect_config": inspect_config,
        "display_name": display_name,
    }

    # Convert the project id into a full resource id.
    parent = f"projects/{project}"

    # Call the API.
    response = dlp_client.create_inspect_template(
        request={
            "parent": parent,
            "inspect_template": inspect_template,
            "template_id": template_id,    
        }
    )

    print(f"Successfully created template {response.name}")

llm_log_infotypes = [
    "PHONE_NUMBER", 
    "CREDIT_CARD_NUMBER", 
    "DATE_OF_BIRTH", 
    "EMAIL_ADDRESS", 
    "US_SOCIAL_SECURITY_NUMBER", 
    "PERSON_NAME", 
    "LAST_NAME"
]

create_DLP_template(PROJECT_ID, llm_log_infotypes, TEMPLATE_NAME, TEMPLATE_NAME, 3, 100, False)

# ---- Create Input File and Upload Input to Bucket ----

def create_json_file(bucket_name):
    data = {
        "dlp_mode": "img_redact",
        "video_file_uri": "gs://cloud-samples-data/generative-ai/video/behind_the_scenes_pixel.mp4",
        "image_file_uri": f"gs://{bucket_name}/sensitive-data-images.png",
        "prompt": """Watch each frame in the video carefully and answer the questions.
Only base your answers strictly on what information is available in the video attached.
Do not make up any information that is not part of the video and do not be too
verbose, be to the point.

Questions:
- When is the moment in the image happening in the video? Provide a timestamp.
- What is the context of the moment and what does the narrator say about it?
- Does image contain SSN 333-22-4567
- Does image contain Phone number 858-333-1111"""
    }

    filename = "inputfile.json"
    with open(filename, "w") as file:
        json.dump(data, file, indent=2)  # Indent for readability

# Create the input JSON file
create_json_file(INPUT_BUCKET)

print("JSON file inputfile.json created successfully.")

# Upload the input JSON file to the Input Bucket

print(f"Copying inputfile.json to {INPUT_BUCKET}")

input_bucket_client = storage_client.bucket(INPUT_BUCKET)
blob = input_bucket_client.blob(f'assets/inputfile.json')

try:
    with open("inputfile.json", 'rb') as f:  
        blob.upload_from_file(f)  
        print("inputfile.json uploaded to Cloud Storage successfully.")
except FileNotFoundError:
    print("Error: inputfile.json not found in the current directory.")
except PermissionError:
    print("Error: Permission denied to read inputfile.json.")
except Exception as e:  
    print(f"Error uploading file: {e}")

# Add image to Input Bucket

print(f"Copying sensitive-data-images.png to {INPUT_BUCKET}")

def upload_image_to_gcs(bucket_name, source_file_name):
    """Uploads an image to a GCS bucket with the same filename.

    Args:
        bucket_name: Your GCS bucket name (e.g., "your-bucket-name").
        source_file_name: Path to the local image file (e.g., "sensitive-data-images.png").
    """

    storage_client = storage.Client()
    bucket = storage_client.bucket(bucket_name)
    blob = bucket.blob(source_file_name)  # Use the same name for the destination

    try:
        blob.upload_from_filename(source_file_name)
        print(
            f"File {source_file_name} uploaded to gs://{bucket_name}/{source_file_name}"
        )
    except Exception as e:
        print(f"Error uploading file: {e}")

image_file_name = "sensitive-data-images.png"

# Check if the file exists
if not os.path.isfile(image_file_name):
    print(f"Error: File '{image_file_name}' not found.")
else:
    # Upload the image to GCS
    upload_image_to_gcs(INPUT_BUCKET, image_file_name)
