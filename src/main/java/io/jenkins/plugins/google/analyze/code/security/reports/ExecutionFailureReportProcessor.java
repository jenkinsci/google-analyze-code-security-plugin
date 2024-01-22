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

package io.jenkins.plugins.google.analyze.code.security.reports;

import io.jenkins.plugins.google.analyze.code.security.commons.Config;
import io.jenkins.plugins.google.analyze.code.security.commons.ReportConstants;
import io.jenkins.plugins.google.analyze.code.security.model.IACValidationService.response.ErrorReportRequest;
import io.jenkins.plugins.google.analyze.code.security.model.HTMLIndent;
import io.jenkins.plugins.google.analyze.code.security.model.PluginConfig;
import io.jenkins.plugins.google.analyze.code.security.utils.ReportUtils;
import org.apache.commons.lang.StringUtils;
import java.util.ArrayList;
import java.util.List;

/**
 * ExecutionFailureReportProcessor processes Execution Failure Report.
 *
 * <p>
 * Performs following operations :
 * 1) Report Generation.
 * 2) Report Publishing.
 * </p>
 */
public class ExecutionFailureReportProcessor extends ReportProcessor<ErrorReportRequest> {
    public static ExecutionFailureReportProcessor instance;

    /**
     * Returns an instance of {@link ExecutionFailureReportProcessor}
     */
    public static ExecutionFailureReportProcessor getInstance() {
        if (instance == null) {
            instance = new ExecutionFailureReportProcessor();
        }
        return instance;
    }

    private ExecutionFailureReportProcessor() {
    }

    /**
     * Generate an HTML Report encapsulating error and corresponding request details.
     *
     * @param errorReportRequest contains request arguments for generating error report.
     * @return HTML ErrorReport as String.
     */
    @Override
    public String generateReport(final ErrorReportRequest errorReportRequest) {
        final List<String> content = new ArrayList<>();
        content.add(ReportConstants.REPORT_OPEN_HTML.replace(/*target=*/ "$REPORT_TITLE$", Config.PLUGIN_ERROR_REPORT_NAME));

        content.add(ReportUtils.buildHTMLDivWithKeyAndOptionalValueEntry(HTMLIndent.ZERO, /*key=*/ "File Scanned",
                errorReportRequest.getValidationFilePath()));
        content.add(ReportUtils.buildHTMLDivWithKeyAndOptionalValueEntry(HTMLIndent.ZERO, /*key=*/ "Start Time(UTC):",
                errorReportRequest.getScanStartTime()));
        content.add(ReportUtils.buildHTMLDivWithKeyAndOptionalValueEntry(HTMLIndent.ZERO, /*key=*/ "End Time(UTC):",
                errorReportRequest.getScanEndTime()));
        content.add(ReportUtils.buildHTMLDivWithKeyAndOptionalValueEntry(HTMLIndent.ZERO, /*key=*/ "Plugin Config:",
                StringUtils.EMPTY));
        addConfigParams(errorReportRequest.getPluginConfig(), content);
        content.add(ReportUtils.buildHTMLDivWithKeyAndOptionalValueEntry(HTMLIndent.ZERO, /*key=*/ "Error Code:",
                errorReportRequest.getErrorCode()));
        content.add(ReportUtils.buildHTMLDivWithKeyAndOptionalValueEntry(HTMLIndent.ZERO, /*key=*/ "Error Message:",
                errorReportRequest.getError()));

        content.add(ReportConstants.REPORT_CLOSE_HTML);
        content.removeIf(String::isEmpty);
        return StringUtils.join(content, "\n");
    }

    private void addConfigParams(final PluginConfig pluginConfig, final List<String> content) {
        content.add(ReportUtils.buildHTMLDivWithKeyAndOptionalValueEntry(HTMLIndent.SINGLE, /*key=*/ "Organization ID:",
                pluginConfig.getOrgID()));
        content.add(ReportUtils.buildHTMLDivWithKeyAndOptionalValueEntry(HTMLIndent.SINGLE, /*key=*/ "Scan File Name:",
                pluginConfig.getScanFileName()));
        content.add(ReportUtils.buildHTMLDivWithKeyAndOptionalValueEntry(HTMLIndent.SINGLE, /*key=*/ "Scan File Path:",
                pluginConfig.getFilePath()));
        content.add(ReportUtils.buildHTMLDivWithKeyAndOptionalValueEntry(HTMLIndent.SINGLE, /*key=*/ "Scan Time Out:",
                String.valueOf(pluginConfig.getScanTimeOut())));
        content.add(ReportUtils.buildHTMLDivWithKeyAndOptionalValueEntry(HTMLIndent.SINGLE, /*key=*/ "Fail Silently " +
                "Configuration:", String.valueOf(pluginConfig.getFailSilentlyOnPluginFailure())));
        processAssetViolationConfig(pluginConfig, content);
    }

    private void processAssetViolationConfig(final PluginConfig pluginConfig, final List<String> content) {
        if (pluginConfig.getIgnoreAssetViolation().equals(true)) {
            content.add(ReportUtils.buildHTMLDivWithKeyAndOptionalValueEntry(HTMLIndent.SINGLE, /*key=*/ "Ignore Asset " +
                    "Violation:", String.valueOf(true)));
            return;
        }
        final List<String> violationConfigs = new ArrayList<>();
        violationConfigs.add("Fail Build On Asset Violation : ");
        violationConfigs.add(String.format("{ConfigAggregator : %s}", pluginConfig.getConfigAggregator().name()));
        violationConfigs.add("SeverityConfigs: [");
        if (pluginConfig.getAssetViolationConfigs() != null) {
            pluginConfig.
                    getAssetViolationConfigs().forEach((config -> violationConfigs.add(String.format("{%s : %s}",
                            config.getSeverity().name(), config.getCount()))));
        }
        violationConfigs.add("]");
        content.add(ReportUtils.buildHTMLDivWithKeyAndOptionalValueEntry(HTMLIndent.SINGLE, "Asset Violation " +
                "Configuration:", StringUtils.join(violationConfigs, /*separator=*/ " ")));
        content.add(ReportUtils.buildHTMLDivWithKeyAndOptionalValueEntry(HTMLIndent.SINGLE, /*key=*/ "Ignore Asset " +
                "Violation:", String.valueOf(false)));
    }
}
