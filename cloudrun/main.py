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

import base64
import sys
import json
import os
import hashlib
import time
from typing import List
from flask import Flask, request, jsonify
import google.auth
import proto
import ast
import mimetypes
import google.cloud.dlp
from google.cloud import logging
from google.cloud import storage
import vertexai
from google.cloud import aiplatform
from vertexai.generative_models import GenerativeModel, Part


app = Flask(__name__)

credentials = google.auth.default()
project = os.environ.get('PROJECT_ID')
storage_client = storage.Client()

@app.route("/", methods=["GET"])
def process_requests():
    bucket_name = os.environ.get('INPUT_BUCKET')
    file_name = os.environ.get('INPUTFILE_NAME')
    inputfile_name = f"assets/{file_name}"
    bucket = storage_client.bucket(bucket_name)
    blob = bucket.blob(inputfile_name)
    file_content = blob.download_as_text()
    file_content = ast.literal_eval(file_content)
 
    # Read inputs
    project_id = project
    dlp_mode = file_content["dlp_mode"]

    video_file_uri = file_content["video_file_uri"]
    image_file_uri = file_content["image_file_uri"]
    prompt = file_content["prompt"]

    mime_type = "video/"+video_file_uri.split(".")[-1]
    video_file = Part.from_uri(video_file_uri, mime_type=mime_type)

    mime_type = "image/"+ image_file_uri.split(".")[-1]
    image_file = Part.from_uri(image_file_uri, mime_type=mime_type)
    
    contents = [
      video_file,
      image_file,
      prompt,
    ]
    try:
        result = prompt_fn(contents,dlp_mode)
        return jsonify(result)
    except Exception as e:
        print(f"error: {e}")
        return ("", 500)


def write_entry(logger_name, message):
    """Writes log entries to the given logger."""
    try:
        logging_client = logging.Client()
        logger_name = "llm-prompt"
        # This log can be found in the Cloud Logging console under 'Custom Logs'.
        logger = logging_client.logger(logger_name)
        logger.log_struct(
            message, severity="INFO"
        )
    except Exception as e:  # Broad exception handling for robustness
        logging.error(f"Error logging message: {e}")

def generate_checksum(data):
    """Generates a checksum of input data."""

    hash_object = hashlib.new("sha256")
    if isinstance(data, str):  
        data = data.encode('utf-8')  # Convert string to bytes if needed
    hash_object.update(data)
    return hash_object.hexdigest()


def log_object(object_url, checksum):
    """Copies object to GCS bucket"""

    # print(object_url)
    source_bucket = object_url.split("/")[2]
    logging_bucket = os.environ.get('LOGGING_BUCKET')
    blob_name = "/".join(object_url.split("/")[3:])
    destination_blob_name = blob_name.split(".")[0].split("/")[-1] + checksum + "." + blob_name.split(".")[-1]
    # Get references to the buckets and blob
    source_bucket = storage_client.bucket(source_bucket)
    logging_bucket = storage_client.bucket(logging_bucket)
    blob = source_bucket.blob(blob_name)
    
    # Check if blob exists in the source bucket
    if not blob.exists():
        raise FileNotFoundError(f"Blob {blob_name} not found in {source_bucket}.")
  
    new_blob = source_bucket.copy_blob(
        blob, logging_bucket, destination_blob_name,
    )
    return new_blob


def deidentify_with_replace_infotype(
    item: str
) -> None:
    # Instantiate a client
    dlp = google.cloud.dlp_v2.DlpServiceClient()
    
    # Convert the project id into a full resource id.
    parent = f"projects/{project}/locations/global"
    
    info_types = ['US_SOCIAL_SECURITY_NUMBER','CREDIT_CARD_NUMBER','EMAIL_ADDRESS','PERSON_NAME','PHONE_NUMBER','US_DRIVERS_LICENSE_NUMBER','IP_ADDRESS']
    # Construct inspect configuration dictionary
    inspect_config = {"info_types": [{"name": info_type} for info_type in info_types]}

    # Construct deidentify configuration dictionary
    deidentify_config = {
        "info_type_transformations": {
            "transformations": [
                {"primitive_transformation": {"replace_with_info_type_config": {}}}
            ]
        }
    }
    # Call the API
    response = dlp.deidentify_content(
        request={
            "parent": parent,
            "deidentify_config": deidentify_config,
            "inspect_config": inspect_config,
            "item": {"value": item},
        }
    )
    return(response.item.value)

def deidentify_with_deterministic(
    input_str: str,
) -> None:
    """Deidentifies sensitive data in a string using deterministic encryption.
    """

    # Instantiate a client
    dlp = google.cloud.dlp_v2.DlpServiceClient()

    # Convert the project id into a full resource id.
    parent = f"projects/{project}/locations/global"
    bucket_name = os.environ.get('WRAPPEDKEY_BUCKET')
    wrapped_key = "assets/wrapped_key"
    # The wrapped key is base64-encoded, but the library expects a binary
    # string, so decode it here.
    storage_client = storage.Client()
    bucket = storage_client.bucket(bucket_name)
    blob = bucket.blob(wrapped_key)
    surrogate_type ="LLM"
 
    wrapped_key = blob.download_as_text(encoding="utf-8")
    wrapped_key = base64.b64decode(wrapped_key)
    key_name = f"projects/{project}/locations/global/keyRings/{os.environ.get('KEYRING_NAME')}/cryptoKeys/{os.environ.get('KEY_NAME')}"
    # Construct Deterministic encryption configuration dictionary
    crypto_replace_deterministic_config = {
        "crypto_key": {
            "kms_wrapped": {"wrapped_key": wrapped_key, "crypto_key_name": key_name}
        },
    }

    # Add surrogate type
    if surrogate_type:
        crypto_replace_deterministic_config["surrogate_info_type"] = {
            "name": surrogate_type
        }
    info_types = ['US_SOCIAL_SECURITY_NUMBER','CREDIT_CARD_NUMBER','EMAIL_ADDRESS','PERSON_NAME','PHONE_NUMBER','US_DRIVERS_LICENSE_NUMBER','IP_ADDRESS']
    # Construct inspect configuration dictionary
    inspect_config = {"info_types": [{"name": info_type} for info_type in info_types]}

    # Construct deidentify configuration dictionary
    deidentify_config = {
        "info_type_transformations": {
            "transformations": [
                {
                    "primitive_transformation": {
                        "crypto_deterministic_config": crypto_replace_deterministic_config
                    }
                }
            ]
        }
    }

    # Convert string to item
    item = {"value": input_str}

    # Call the API
    response = dlp.deidentify_content(
        request={
            "parent": parent,
            "deidentify_config": deidentify_config,
            "inspect_config": inspect_config,
            "item": item,
        }
    )
    return(response.item.value)

def redact_image(
    project,
    input_filename,
    output_filename,
    inspect_template,
    include_quotes,
    mime_type=None,
):
    """
    Taken from https://github.com/GoogleCloudPlatform/dlp-pdf-redaction/blob/main/src/dlp-runner/main.py

    Uses the Data Loss Prevention API to redact protected data in an image.
    """
    dlp = google.cloud.dlp_v2.DlpServiceClient()
    # If mime_type is not specified, guess it from the filename.
    if mime_type is None:
        mime_guess = mimetypes.MimeTypes().guess_type(input_filename)
        mime_type = mime_guess[0] or "application/octet-stream"

    # Select the content type index from the list of supported types.
    supported_content_types = {
        None: 0,  # "Unspecified"
        "image/jpeg": 1,
        "image/bmp": 2,
        "image/png": 3,
        "image/svg": 4,
        "text/plain": 5,
    }
    content_type_index = supported_content_types.get(mime_type, 0)

    # Construct the byte_item, containing the file's byte data.
    with open(input_filename, mode="rb") as f:
        byte_item = {"type_": content_type_index, "data": f.read()}

    # Convert the project id into a full resource id.
    parent = f"projects/{project}"

    inspect_template = dlp.get_inspect_template(name=inspect_template)

    # Include quote (redacted data) in findings result
    inspect_template.inspect_config.include_quote = include_quotes

    # Call the API
    response = dlp.redact_image(
        request={
            "parent": parent,
            "inspect_config": inspect_template.inspect_config,
            "byte_item": byte_item,
            "include_findings": True
        })

    # Write out the redacted image to local disk
    with open(output_filename, mode="wb") as f:
        f.write(response.redacted_image)

    return proto.Message.to_dict(response.inspect_result)["findings"]


def split_logs_by_length(text, chunk_size=1250):
    """Splits a string into chunks of a specified maximum length."""
    return [text[i:i+chunk_size] for i in range(0, len(text), chunk_size)]


def llm_function(request):

    try:
        vertexai.init(project=project, location=os.environ.get('LOCATION'))
        model = GenerativeModel(model_name="gemini-1.5-flash-001")

        # Send text to Gemini
        response = model.generate_content(request)
        text_content = response.text
        if text_content:
            return text_content  # Success!
        else:
                print(f"Empty response. Retrying...")
    except Exception as e:  # Broad exception handling
        print(f"Error: {e}")  



def prompt_fn(contents, dlp_mode):
    """Responds to any HTTP request
    """
    if contents !="":
        contents = contents
        milliseconds = int(time.time() * 1000)
        checksum = generate_checksum(str(contents))
        checksum = checksum + str(milliseconds)
        log_split = split_logs_by_length(str(contents))

        #logs object to logging bucket with appended prmpt checksum
        log_object_1 = log_object(contents[0].file_data.file_uri, checksum)
        log_object_2 = log_object(contents[1].file_data.file_uri, checksum)
        for log in log_split:
            dictRequest = {
                "Prompt":log,
                "checksum": checksum,
                "objectPath": str(log_object_1),
                "objectPath2": str(log_object_2) 
            }
            # Log LLM response here. Comment out the line below if you don't want prompt to be written to logging
            write_entry("llm-prompt", dictRequest) 
        
        if dlp_mode == "encrypt":         
            # Call DLP deterministic encrypt prompt
            dlp_encrypt = deidentify_with_deterministic(str(contents))
            print(dlp_encrypt)
            log_split_dlp = split_logs_by_length(str(dlp_encrypt))
            
            for log in log_split_dlp:
                dictdlp = {
                    "DLP_Output":log,
                    "checksum": checksum,
                    "objectPath": str(log_object_1),
                    "objectPath2": str(log_object_2)         
                }
                # Log DLP Prompt response here
                write_entry("llm-prompt", dictdlp)
            
            #send raw prompt response to gemini   
            llm_response = llm_function(contents)
            dlp_response = deidentify_with_deterministic(llm_response)
            print(dlp_response)
             # Log LLM response here
            split_dlp_response = split_logs_by_length(str(dlp_response))
            for log in split_dlp_response:
                dictResponse = {
                    "Response": str(log),
                    "checksum": checksum, 
                    "objectPath": str(log_object_1),
                    "objectPath2": str(log_object_2)    
                }
                write_entry("llm-prompt", dictResponse) 

        if dlp_mode == "mask":          # Call DLP mask prompt          
            dlp_prompt = deidentify_with_replace_infotype(str(contents))
            print(dlp_prompt)
            log_split_dlp = split_logs_by_length(str(dlp_prompt))
            
            for log in log_split_dlp:
                dictdlp = {
                    "DLP_Output":log,
                    "checksum": checksum,
                    "objectPath": str(log_object_1),
                    "objectPath2": str(log_object_2)          
                }
                # Log DLP Prompt response here
                write_entry("llm-prompt", dictdlp) 


            #send raw prompt response to gemini   
            llm_response = llm_function(contents)

            # Call DLP here for with LLM response
            dlp_response = deidentify_with_replace_infotype(llm_response)
            print(dlp_response)

            split_dlp_response = split_logs_by_length(str(dlp_response))
            for log in split_dlp_response:

                dictResponse = {
                    "Response": str(log),
                    "checksum": checksum,
                    "objectPath": str(log_object_1),
                    "objectPath2": str(log_object_2)     
                }
                # Log LLM response here
                write_entry("llm-prompt", dictResponse) 

        if dlp_mode == "img_redact":          # Call DLP redact image
            storage_client = storage.Client()
            bucket_name = contents[1].file_data.file_uri.split("/")[2]
            input_file = contents[1].file_data.file_uri.split("/")[-1]
            print(input_file)
            input_bucket_client = storage_client.get_bucket(bucket_name)
            blob_file = input_bucket_client.get_blob(input_file)
            blob_file.download_to_filename(input_file)

            tmp_file_redacted = f"redacted_{checksum}+{input_file}"
            print(f"Input file downloaded from GCS to {input_file}")
            template_name = os.environ.get('TEMPLATE_NAME')
            inspect_template = f"projects/{project}/locations/global/inspectTemplates/{template_name}"
            # redact file using DLP
            findings = redact_image(project, input_file, tmp_file_redacted,
                            inspect_template, False)
            print(f"Redacted image saved to file {tmp_file_redacted}")

            # upload redacted image to bucket
            output_bucket_client = storage_client.get_bucket(bucket_name)
            out_blob = output_bucket_client.blob(tmp_file_redacted)
            out_blob.upload_from_filename(tmp_file_redacted)
            print(
                f"Redacted image uploaded to gs://{bucket_name}/{tmp_file_redacted}") 

            dlp_prompt = deidentify_with_replace_infotype(str(contents))
            print(dlp_prompt)
            log_split_dlp = split_logs_by_length(str(dlp_prompt))            
            for log in log_split_dlp:
                dictdlp = {
                    "DLP_Output":log,
                    "checksum": checksum,
                    "objectPath": str(log_object_1),
                    "objectPath2": str(log_object_2)          
                }
                # Log DLP Prompt response here
                write_entry("llm-prompt", dictdlp) 


            #send raw prompt response to gemini   
            llm_response = llm_function(contents)

            # Call DLP here for with LLM response
            dlp_response = deidentify_with_replace_infotype(llm_response)
            print(dlp_response)

            split_dlp_response = split_logs_by_length(str(dlp_response))
            for log in split_dlp_response:

                dictResponse = {
                    "Response": str(log),
                    "checksum": checksum,
                    "objectPath": str(log_object_1),
                    "objectPath2": str(log_object_2)     
                }
                # Log LLM response here
                write_entry("llm-prompt", dictResponse)
    else:
        return f'No Prompt detected!'

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=int(os.environ.get("PORT", 8080)))
