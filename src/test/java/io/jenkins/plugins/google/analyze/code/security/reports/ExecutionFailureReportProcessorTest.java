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
import io.jenkins.plugins.google.analyze.code.security.model.ConfigAggregator;
import io.jenkins.plugins.google.analyze.code.security.model.IACValidationService.response.ErrorReportRequest;
import io.jenkins.plugins.google.analyze.code.security.model.PluginConfig;
import io.jenkins.plugins.google.analyze.code.security.utils.FileUtils;
import io.jenkins.plugins.google.analyze.code.security.violationConfig.AssetViolationConfig;
import io.jenkins.plugins.google.analyze.code.security.violationConfig.CriticalSeverityConfig;
import io.jenkins.plugins.google.analyze.code.security.violationConfig.HighSeverityConfig;
import io.jenkins.plugins.google.analyze.code.security.commons.TestUtil;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.junit.MockitoJUnitRunner;
import java.io.IOException;
import java.util.HashMap;
import java.util.List;

import static io.jenkins.plugins.google.analyze.code.security.commons.TestUtil.DUMMY_FILE_PATH;
import static io.jenkins.plugins.google.analyze.code.security.commons.TestUtil.DUMMY_ORG_ID;
import static io.jenkins.plugins.google.analyze.code.security.commons.TestUtil.DUMMY_SCAN_END_TIME;
import static io.jenkins.plugins.google.analyze.code.security.commons.TestUtil.DUMMY_SCAN_START_TIME;
import static org.junit.Assert.assertEquals;

/**
 * ExecutionFailureReportProcessorTest for {@link ExecutionFailureReportProcessor}
 */
@RunWith(MockitoJUnitRunner.class)
public class ExecutionFailureReportProcessorTest {
    private ExecutionFailureReportProcessor executionFailureReportProcessor;

    @Before
    public void setup() {
        executionFailureReportProcessor = ExecutionFailureReportProcessor.getInstance();
    }

    @Test
    public void generateReport_ignoreAssetViolationConfigFalse_reportMatchSuccess() throws IOException {
        final String report = executionFailureReportProcessor.generateReport(
                buildErrorReportRequest(/*ignoreAssetViolation=*/ false, List.of(new HighSeverityConfig(/*count=*/ 1),
                        new CriticalSeverityConfig(/*count=*/ 2))));

        Assert.assertEquals(FileUtils.readFromInputStream(getClass()
                .getResourceAsStream("/errorReportWithIgnoreAssetViolationConfigFalse.html")), /*actual=*/ report+"\n");
    }

    @Test
    public void generateReport_ignoreAssetViolationConfigTrue_reportMatchSuccess() throws IOException {
        final String report = executionFailureReportProcessor.generateReport(buildErrorReportRequest(/*ignoreAssetViolation=*/ true,
                List.of(new HighSeverityConfig(/*count=*/ 1), new CriticalSeverityConfig(/*count=*/ 2))));

        assertEquals(FileUtils.readFromInputStream(getClass()
                .getResourceAsStream("/errorReportWithIgnoreAssetViolationConfigTrue.html")), /*actual=*/ report+"\n");
    }

    private ErrorReportRequest buildErrorReportRequest(final Boolean ignoreAssetViolation,
                                                       final List<AssetViolationConfig> assetViolationConfigs) {
        final PluginConfig pluginConfig = PluginConfig.builder()
                .assetViolationConfigs(assetViolationConfigs)
                .orgID(DUMMY_ORG_ID)
                .failSilentlyOnPluginFailure(true)
                .ignoreAssetViolation(ignoreAssetViolation)
                .configAggregator(ConfigAggregator.OR)
                .scanFileName("testFile")
                .scanTimeOut(Config.SCAN_TIMEOUT_DEFAULT)
                .build();
        return ErrorReportRequest.builder()
                .error("Invalid Config")
                .errorCode("400")
                .validationFilePath(TestUtil.DUMMY_VALIDATE_FILE_PATH)
                .reportWritePath(ReportConstants.PLUGIN_ERROR_REPORT_PATH)
                .scanStartTime(DUMMY_SCAN_START_TIME)
                .scanEndTime(DUMMY_SCAN_END_TIME)
                .workspacePath(DUMMY_FILE_PATH)
                .workspaceContents(new HashMap<>())
                .pluginConfig(pluginConfig)
                .build();
    }
}
