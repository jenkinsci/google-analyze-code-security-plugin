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

import static io.jenkins.plugins.google.analyze.code.security.commons.TestUtil.*;
import static org.junit.Assert.assertEquals;

import io.jenkins.plugins.google.analyze.code.security.commons.ReportConstants;
import io.jenkins.plugins.google.analyze.code.security.commons.TestUtil;
import io.jenkins.plugins.google.analyze.code.security.model.IACValidationService.response.IACScanReportRequest;
import io.jenkins.plugins.google.analyze.code.security.model.IACValidationService.response.IaCValidationReport;
import io.jenkins.plugins.google.analyze.code.security.model.IACValidationService.response.Violation;
import io.jenkins.plugins.google.analyze.code.security.utils.FileUtils;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.junit.MockitoJUnitRunner;

/**
 * IACScanReportProcessorTest for {@link IACScanReportProcessor}
 */
@RunWith(MockitoJUnitRunner.class)
public class IACScanReportProcessorTest {
    private IACScanReportProcessor iacScanReportProcessor;

    @Before
    public void setup() {
        iacScanReportProcessor = IACScanReportProcessor.getInstance();
    }

    @Test
    public void generateReport_nonEmptyViolations_reportMatchSuccess() throws IOException {
        final String report = iacScanReportProcessor.generateReport(buildIACScanReportRequest(DUMMY_VIOLATIONS));

        Assert.assertEquals(
                FileUtils.readFromInputStream(
                        getClass().getResourceAsStream(/*name=*/ "/iacScanReportNonEmptyViolation.html")),
                /*actual=*/ report + "\n");
    }

    @Test
    public void generateReport_EmptyViolations_reportMatchSuccess() throws IOException {
        final String report = iacScanReportProcessor.generateReport(buildIACScanReportRequest(new ArrayList<>()));

        assertEquals(
                FileUtils.readFromInputStream(
                        getClass().getResourceAsStream(/*name=*/ "/iacScanReportEmptyViolation.html")),
                /*actual=*/ report + "\n");
    }

    private IACScanReportRequest buildIACScanReportRequest(final List<Violation> violations) {
        IaCValidationReport report= IaCValidationReport.builder().violations(violations).note(DUMMY_NOTE).build();
        return IACScanReportRequest.builder()
                .validationFilePath(TestUtil.DUMMY_VALIDATE_FILE_PATH)
                .reportWritePath(ReportConstants.BUILD_SUMMARY_REPORT_PATH)
                .scanStartTime(DUMMY_SCAN_START_TIME)
                .scanEndTime(DUMMY_SCAN_END_TIME)
                .workspacePath(DUMMY_FILE_PATH)
                .workspaceContents(new HashMap<>())
                .report(report)
                .build();
    }
}
