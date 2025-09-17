#!/usr/bin/env python3
"""
Databricks-specific code with UDF I/O issues
Should trigger: DBX001_UDF_IO
"""
import json

import requests
from pyspark.sql.functions import udf
from pyspark.sql.types import StringType


# DBX001_UDF_IO - I/O operations inside UDF (problematic)
@udf(returnType=StringType())
def dangerous_udf(user_id):
    """This UDF performs I/O operations which is bad for performance"""
    # File I/O inside UDF - will cause serialization issues
    with open(f"/tmp/user_{user_id}.json", "w") as f:
        json.dump({"processed": True}, f)

    # Network I/O inside UDF - will fail in distributed execution
    response = requests.get(f"https://api.example.com/user/{user_id}")
    return response.json().get("status", "unknown")


# Another problematic UDF with file operations
def process_with_io():
    @udf(returnType=StringType())
    def file_reading_udf(path):
        # File operations in UDF
        with open(path, "r") as f:
            return f.read()[:100]

    return file_reading_udf


# Safe UDF (should NOT trigger warnings)
@udf(returnType=StringType())
def safe_udf(user_name, department):
    """Pure computation UDF - no I/O operations"""
    if department == "engineering":
        return f"{user_name}_eng"
    return f"{user_name}_other"


# Safe approach - I/O outside UDF
def safe_data_processing(df):
    """Proper pattern: I/O outside, pure UDFs for transformation"""
    # Do I/O operations outside UDF
    lookup_data = {}
    with open("/tmp/lookup.json", "r") as f:
        lookup_data = json.load(f)

    # Create broadcast variable for the lookup data
    broadcast_lookup = spark.sparkContext.broadcast(lookup_data)

    # Pure UDF that uses broadcast data
    @udf(returnType=StringType())
    def lookup_udf(key):
        return broadcast_lookup.value.get(key, "unknown")

    return df.withColumn("enriched", lookup_udf(df.key_column))
