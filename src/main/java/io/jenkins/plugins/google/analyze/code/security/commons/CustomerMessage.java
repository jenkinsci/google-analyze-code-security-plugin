/*
 * Copyright 2024 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package io.jenkins.plugins.google.analyze.code.security.commons;

/**
 * CustomerMessage represents messages displayed to Customers as a part of FormValidation and
 * Plugin Execution Failure Report.
 */
public final class CustomerMessage {
    private CustomerMessage() {
    }

    public final static String INVALID_ORG_ID = "Provide a valid Google Cloud organization ID.";
    public final static String INVALID_SCAN_FILE_NAME = "You must enter a Scan File Name.";
    public final static String INVALID_SCAN_TIMEOUT = String.format("Invalid Scan Timeout. Timeout should be between " +
            "MIN: [%s] & MAX : [%s] Millisecond.", Config.SCAN_TIMEOUT_MIN, Config.SCAN_TIMEOUT_MAX);
    public final static String INVALID_VIOLATION_COUNT_CONFIGURATION = "Invalid Violation Count. Violation should be " +
            "positive integer";
    public final static String INVALID_SEVERITY_CONFIG = "Invalid Asset Violation Config Duplicate entries exist for : %s";
    public final static String INVALID_CREDENTIAL_INSUFFICIENT_PERMISSION = "Credentials Corresponding to OrgID : %s have insufficient " +
            "permissions";
    public final static String CREDENTIAL_PAIR_VALIDATION_ERROR = "Encountered Error while Validating Credential : %s";
    public final static String VALID_CREDENTIAL_PAIR = "Successfully Verified Credentials";
    public final static String INVALID_SCC_CREDENTIAL = "Invalid SCC Credential for OrgID : [%s]";
    public final static String MALFORMED_SCC_CREDENTIAL = "[Invalid Request] Malformed SCC Credential";
    public final static String CREDENTIAL_NOT_FOUND = "Credential Not Found for OrgID : [%s]";
    public final static String DUPLICATE_CREDENTIALS_FOUND = "Received Duplicate credentials for OrgId : [%s]";
    public final static String INVALID_CONFIG = "[Invalid Config] Violations : [%s]";
    public final static String INVALID_REQUEST = "[Invalid Request] Violations : [%s]";
    public final static String FILE_NOT_FOUND = "Scan File not found in the workspace directory";
    public final static String INVALID_SCAN_FILE_SIZE = "Found Scan File with size : [%s] Bytes, Max limit : [%s] Bytes";
    public final static String MALFORMED_SCAN_FILE = "[Invalid Request] Scan File found to be Malformed";
    public final static String EMPTY_ASSET_VIOLATION_CONFIG = "[Invalid Config] Asset Violation Config can not be empty" +
            " with ignore asset violation set to false";
    public final static String IAC_VALIDATION_EXCEPTION_MSG = "Failed to Scan file due to following error : [%s]";
    public final static String WORKSPACE_PATH_MISSING = "Failed to fetch Workspace Path";
    public final static String CREDENTIAL_VALIDATION_INTERNAL_ERROR = "[Internal Error] Unable to validate " +
            "credential due to internal error : [%s]";
}
