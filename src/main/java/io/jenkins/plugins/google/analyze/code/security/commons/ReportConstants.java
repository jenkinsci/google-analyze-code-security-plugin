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
 * ReportConstants provides constants for Report related operations.
 */
public final class ReportConstants {

    private ReportConstants() {
    }

    public static final String BUILD_SUMMARY_REPORT_PATH = "/GoogleAnalyzeCodeSecurity_ViolationSummary.html";
    public static final String PLUGIN_ERROR_REPORT_PATH = "/GoogleAnalyzeCodeSecurity_ErrorSummary.html";
    public static final String STYLES_CSS_PATH = "/styles.css";

    // Needed for testing credential validity while registering SCC Credential in Jenkins.
    public static final String DUMMY_INVALID_IAC_FILE = "{ \"provider\" : \"google\" }";
    public static final String INDENT_CLASS_DIV = "<div class=\"row indent-$INDENT_LEVEL_PLACEHOLDER$\">";
    public static final String DIV_CLOSE = "</div>";
    public static final String KEY_CLASS_DIV = "<div class=\"row--key\">$KEY_PLACEHOLDER$</div>";
    public static final String VALUE_CLASS_DIV = "<div class=\"row--value\">$VALUE_PLACEHOLDER$</div>";
    public static final String REPORT_OPEN_HTML = "<!DOCTYPE html>\n" +
            "<html lang=\"en\">\n" +
            "  <head>\n" +
            "    <meta charset=\"UTF-8\">\n" +
            "    <link rel=\"stylesheet\" href=\"./styles.css\">\n" +
            "  </head>\n" +
            "  <body>\n" +
            "    <h1 class=\"title\">$REPORT_TITLE$</h1>";
    public static final String REPORT_CLOSE_HTML = " </body>\n</html>";
}
