# Databricks notebook source
# Databricks notebook source
import pyspark.sql.functions as F
from pyspark.sql.types import StructType, StructField, StringType, IntegerType
import requests
import json

# ===============================
# Event Hub Configuration
# ===============================

KAFKA_BATCH_OPTIONS = {
    "kafka.bootstrap.servers": BROKER,
    "kafka.sasl.mechanism": "PLAIN",
    "kafka.security.protocol": "SASL_SSL",
    "kafka.sasl.jaas.config": EH_SASL,
    "failOnDataLoss": "false",
    "subscribe": CONSUMER_TOPIC,
    "startingOffsets": "earliest",
    "endingOffsets": "latest"
}

# COMMAND ----------

# ===============================
# Define Schema for Parsing
# ===============================
lead_schema = StructType([
    StructField("Id", StructType([
        StructField("Sequence", StringType()),
        StructField("Source", StringType()),
        StructField("Name", StringType())
    ])),
    StructField("Val", StringType())
])

# Schema for Event Hub payload from Function App (after failure)
event_schema = StructType([
    StructField("LeadData", lead_schema),
    StructField("RequestId", StringType())
])

# COMMAND ----------

# ===============================
# Read Event Hub Data
# ===============================
raw_df = (
    spark.read.format("kafka")
    .options(**KAFKA_BATCH_OPTIONS)
    .load()
)

# Parse Kafka value as JSON with schema
parsed_df = raw_df.withColumn(
    "data",
    F.from_json(F.col("value").cast("string"), event_schema)
).filter(F.col("data").isNotNull())

# Extract RequestId and LeadData for processing
new_events_df = parsed_df.select(
    F.col("data.RequestId").alias("request_id"),
    F.col("data.LeadData").alias("lead_data")
).filter(F.col("request_id").isNotNull() & F.col("lead_data").isNotNull())

display(new_events_df)  # Check parsed records

# COMMAND ----------

# ===============================
# Submit Lead API Configuration
# ===============================
import requests
import json

# TODO: Update with your actual Function App URL
SUBMIT_LEAD_API_URL = "https://your-function-app.azurewebsites.net/api/SubmitLead"

def call_submit_lead_api(lead_data_dict, is_retry=False):
    """
    Call the SubmitLead API with proper query parameter for retry jobs
    Returns: (status_code, response_json)
    """
    headers = {
        "Content-Type": "application/json"
    }
    
    # Prepare URL with query parameter for retry jobs
    url = SUBMIT_LEAD_API_URL
    if is_retry:
        url += "?retryJob=true"
    
    # Prepare payload in the format expected by SubmitLead API
    payload = {
        "Id": lead_data_dict.get("Id", {}),
        "Val": lead_data_dict.get("Val", "")
    }
    
    try:
        response = requests.post(
            url,
            headers=headers,
            json=payload,
            timeout=30
        )
        
        response_json = {}
        try:
            response_json = response.json()
        except:
            response_json = {"message": response.text}
            
        return response.status_code, response_json
        
    except requests.exceptions.Timeout:
        return 408, {"message": "Request timeout"}
    except requests.exceptions.RequestException as e:
        return 500, {"message": f"Request failed: {str(e)}"}

# COMMAND ----------

# ===============================
# Create Tables
# ===============================
spark.sql("""
CREATE TABLE IF NOT EXISTS lead_request_tracking (
    request_id STRING,
    retry_count INT,
    last_retry_status STRING,
    delivr_response_code_and_message STRING,
    create_ts TIMESTAMP,
    updated_ts TIMESTAMP
)
USING DELTA
""")

# COMMAND ----------

# MAGIC %sql
# MAGIC SELECT * FROM lead_request_tracking ORDER BY create_ts DESC LIMIT 10;

# COMMAND ----------

from pyspark.sql import Row
from datetime import datetime

# === Function to insert new tracking records ===
def insert_new_request_tracking(request_id):
    """Insert new request with retry_count=0 and empty status"""
    now_ts = datetime.utcnow()
    
    # Insert tracking record
    tracking_data = spark.createDataFrame([
        Row(
            request_id=request_id,
            retry_count=0,
            last_retry_status="",
            delivr_response_code_and_message="",
            create_ts=now_ts,
            updated_ts=now_ts
        )
    ])
    tracking_data.createOrReplaceTempView("new_requests")
    
    spark.sql("""
    MERGE INTO lead_request_tracking tgt
    USING new_requests src
    ON tgt.request_id = src.request_id
    WHEN NOT MATCHED THEN INSERT (
      request_id,
      retry_count,
      last_retry_status,
      delivr_response_code_and_message,
      create_ts,
      updated_ts
    ) VALUES (
      src.request_id,
      src.retry_count,
      src.last_retry_status,
      src.delivr_response_code_and_message,
      src.create_ts,
      src.updated_ts
    )
    """)

# === Function to update tracking after retry ===
def update_request_tracking_after_retry(request_id, last_retry_status, delivr_response):
    """Update existing request after retry attempt"""
    now_ts = datetime.utcnow()

    new_data = spark.createDataFrame([
        Row(
            request_id=request_id,
            last_retry_status=last_retry_status,
            delivr_response_code_and_message=delivr_response,
            updated_ts=now_ts
        )
    ])
    new_data.createOrReplaceTempView("retry_updates")

    spark.sql("""
    MERGE INTO lead_request_tracking tgt
    USING retry_updates src
    ON tgt.request_id = src.request_id
    WHEN MATCHED THEN UPDATE SET
      tgt.retry_count = tgt.retry_count + 1,
      tgt.last_retry_status = src.last_retry_status,
      tgt.delivr_response_code_and_message = src.delivr_response_code_and_message,
      tgt.updated_ts = src.updated_ts
    """)

# === Step 1: Insert new request_ids from Event Hub (only new ones) ===
print("Step 1: Processing new events from Event Hub...")
new_request_ids = new_events_df.select("request_id").distinct().rdd.map(lambda row: row["request_id"]).collect()

for request_id in new_request_ids:
    insert_new_request_tracking(request_id)
    print(f"Inserted new request_id: {request_id}")

print(f"Processed {len(new_request_ids)} new events from Event Hub")

# COMMAND ----------

# === Step 2: Query for eligible retries ===
print("Step 2: Querying for eligible retry requests...")

eligible_retries = spark.sql("""
SELECT request_id, retry_count, last_retry_status
FROM lead_request_tracking
WHERE retry_count < 4 AND last_retry_status != 'Success'
ORDER BY create_ts ASC
""")

eligible_retry_list = eligible_retries.collect()
print(f"Found {len(eligible_retry_list)} eligible requests for retry")

# COMMAND ----------

# === Step 3: Get lead data for eligible retries and process them ===
print("Step 3: Processing retry requests...")

if len(eligible_retry_list) > 0:
    # Get request_ids for eligible retries
    eligible_request_ids = [row["request_id"] for row in eligible_retry_list]
    
    # Create mapping from Event Hub data for eligible request_ids
    request_to_leaddata = {}
    for row in new_events_df.collect():
        if row["request_id"] in eligible_request_ids:
            # Convert lead data to dictionary
            lead_data_dict = row["lead_data"].asDict(recursive=True) if hasattr(row["lead_data"], 'asDict') else row["lead_data"]
            request_to_leaddata[row["request_id"]] = lead_data_dict
    
    for retry_row in eligible_retry_list:
        request_id = retry_row["request_id"]
        current_retry_count = retry_row["retry_count"]
        
        # Get lead data from Event Hub
        lead_data_dict = request_to_leaddata.get(request_id)
        
        if lead_data_dict is None:
            print(f"Warning: Lead data not found in Event Hub for request_id {request_id}, skipping...")
            continue
        
        # Call SubmitLead API with retry query parameter
        status_code, response_json = call_submit_lead_api(lead_data_dict, is_retry=True)
        
        # Determine retry status based on API response
        if status_code == 200:
            api_status = response_json.get("status", "unknown")
            if api_status == "success":
                last_retry_status = "Success"
            elif api_status == "empty":
                last_retry_status = "Empty"
            else:
                last_retry_status = "Success"  # Default for 200 responses
        else:
            last_retry_status = "Failure"
        
        # Prepare response message
        if "message" in response_json:
            delivr_response = f"{status_code}: {response_json['message']}"
        else:
            delivr_response = f"{status_code}: {str(response_json)}"
        
        # Truncate if too long
        delivr_response = delivr_response[:1000]
        
        # Update tracking table
        update_request_tracking_after_retry(request_id, last_retry_status, delivr_response)
        
        print(f"RequestId: {request_id}, Retry: {current_retry_count + 1}, Status: {status_code}, API Status: {response_json.get('status', 'N/A')}, Response: {delivr_response[:100]}...")

print("Retry processing completed.")