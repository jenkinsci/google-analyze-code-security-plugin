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
 * Config represents tunable configurations across the plugin.
 */
public final class Config {
    private Config() {}

    public static final Integer SCAN_TIMEOUT_MIN = 60000;
    public static final Integer SCAN_TIMEOUT_MAX = 900000;
    public static final Integer SCAN_TIMEOUT_DEFAULT = 60000;
    public static final Integer SCAN_FILE_MAX_SIZE_BYTES = 1000000;
    public static final String PLUGIN_NAME = "Google Analyze Code Security";
    public static final Integer CONNECTION_TIMEOUT_BYTES = 60000;
    public static final Integer CONNECTION_REQUEST_TIMEOUT_BYTES = 60000;

    // set high as we want to bound polling by time spent to a minimum of 5 MIN.
    public static final Integer VALIDATE_ENDPOINT_POLL_MAX_ATTEMPT = 50;
    public static final Integer POLL_ATTEMPT_BUFFER_TIME_MILLIS = 500;
    public static final String PLUGIN_ERROR_REPORT_NAME = "Security Scan Plugin Error Report";
    public static final String SCAN_SUMMARY_REPORT_TITLE = "Google Cloud Security Scan Report";
}
