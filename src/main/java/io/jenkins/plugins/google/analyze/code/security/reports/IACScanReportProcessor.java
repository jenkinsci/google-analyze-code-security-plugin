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
import io.jenkins.plugins.google.analyze.code.security.model.HTMLIndent;
import io.jenkins.plugins.google.analyze.code.security.model.IACValidationService.response.IACScanReportRequest;
import io.jenkins.plugins.google.analyze.code.security.model.IACValidationService.response.PolicyDetails;
import io.jenkins.plugins.google.analyze.code.security.model.IACValidationService.response.PostureDetails;
import io.jenkins.plugins.google.analyze.code.security.model.IACValidationService.response.Severity;
import io.jenkins.plugins.google.analyze.code.security.model.IACValidationService.response.Violation;
import io.jenkins.plugins.google.analyze.code.security.utils.ReportUtils;
import org.apache.commons.lang.StringUtils;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;

/**
 * IACScanReportProcessor generates and publishes IAC Scan Violation Summary.
 *
 * <p>
 * Response for Processing IAC Scan report.
 * Performs following operations :
 * 1) Report Generation.
 * 2) Report Publishing.
 * </p>
 */
public class IACScanReportProcessor extends ReportProcessor<IACScanReportRequest> {
    public static IACScanReportProcessor instance;

    /**
     * Returns an instance of {@link IACScanReportProcessor}
     */
    public static IACScanReportProcessor getInstance() {
        if (instance == null) {
            instance = new IACScanReportProcessor();
        }
        return instance;
    }

    private IACScanReportProcessor() {
    }

    /**
     * Generate an HTML Report encapsulating violation details.
     *
     * @param iacScanReportRequest contains request arguments for generating violation summary report.
     * @return HTML Violation Summary as String.
     */
    @Override
    public String generateReport(final IACScanReportRequest iacScanReportRequest) {
        final List<String> content = new ArrayList<>();
        final List<Violation> violations = iacScanReportRequest.getViolations();

        content.add(ReportConstants.REPORT_OPEN_HTML.replace("$REPORT_TITLE$", Config.SCAN_SUMMARY_REPORT_TITLE));

        content.add(ReportUtils.buildHTMLDivWithKeyAndOptionalValueEntry(HTMLIndent.ZERO, /*key=*/ "Validated file:",
                iacScanReportRequest.getValidationFilePath()));
        content.add(ReportUtils.buildHTMLDivWithKeyAndOptionalValueEntry(HTMLIndent.ZERO, /*key=*/ "Start Time(UTC):",
                iacScanReportRequest.getScanStartTime()));
        content.add(ReportUtils.buildHTMLDivWithKeyAndOptionalValueEntry(HTMLIndent.ZERO, /*key=*/ "End Time(UTC):",
                iacScanReportRequest.getScanEndTime()));

        if (violations.isEmpty()) {
            content.add(ReportUtils.buildHTMLDivWithKeyAndOptionalValueEntry(HTMLIndent.ZERO, /*key=*/ "Summary:",
                    /*value=*/ "No issues found"));
            content.add(ReportConstants.REPORT_CLOSE_HTML);
            content.removeIf(String::isEmpty);
            return StringUtils.join(content,/*separator=*/ "\n");
        }
        content.add(ReportUtils.buildHTMLDivWithKeyAndOptionalValueEntry(HTMLIndent.ZERO, /*key=*/ "Summary:",
                /*value=*/ violations.size() + " issues found"));
        addViolationInfo(violations, content);
        content.add(ReportConstants.REPORT_CLOSE_HTML);
        content.removeIf(String::isEmpty);
        return StringUtils.join(content, /*separator=*/ "\n");
    }

    private void addViolationInfo(final List<Violation> violations, final List<String> content) {
        // sort the map based on severity & fetch unique policies
        final Map<Severity, Set<String>> uniquePoliciesBySeverity =
                new TreeMap<>(Comparator.comparing(Severity::getSeverity));
        final Map<String, List<Violation>> violationsPerPolicy = new HashMap<>();
        violations.forEach(violation -> {
            uniquePoliciesBySeverity.putIfAbsent(violation.getSeverity(), new HashSet<>());
            uniquePoliciesBySeverity.get(violation.getSeverity()).add(violation.getPolicyId());

            violationsPerPolicy.putIfAbsent(violation.getPolicyId(), new ArrayList<>());
            violationsPerPolicy.get(violation.getPolicyId()).add(violation);
        });
        final List<String> issueCountBySeverity = new ArrayList<>();
        uniquePoliciesBySeverity.forEach((severity, policies) -> issueCountBySeverity.add(String.format("%s : %s",
                severity.name(), getViolationCount(policies, violationsPerPolicy))));
        content.add(ReportUtils.buildHTMLDivWithKeyAndOptionalValueEntry(HTMLIndent.ZERO, /*key=*/ "Issues by Severity",
                StringUtils.join(issueCountBySeverity, /*separator=*/ " ")));
        extractViolationDetails(content, violationsPerPolicy, uniquePoliciesBySeverity);
    }

    private void extractViolationDetails(final List<String> content, final Map<String, List<Violation>> violationsPerPolicy,
                                         final Map<Severity, Set<String>> uniquePoliciesBySeverity) {
        uniquePoliciesBySeverity.forEach((severity, policies) -> {
            content.add(ReportUtils.buildHTMLDivWithKeyAndOptionalValueEntry(HTMLIndent.ZERO, severity.name(),
                    StringUtils.EMPTY));
            policies.forEach((policy) -> {
                if (violationsPerPolicy.get(policy).isEmpty()) {
                    return;
                }
                addViolatedPolicyInfo(content, violationsPerPolicy.get(policy).get(0));
                addAssetDetails(content, violationsPerPolicy, policy);
            });

        });
    }

    private Integer getViolationCount(final Set<String> policies,
                                      final Map<String, List<Violation>> violationsPerPolicy) {
        return policies.stream()
                .map(policy -> violationsPerPolicy.get(policy).size())
                .reduce(Integer::sum).orElse(/*other=*/ 0);
    }

    private void addViolatedPolicyInfo(final List<String> content, final Violation violatedPolicyInfo) {
        content.add(ReportUtils.buildHTMLDivWithKeyAndOptionalValueEntry(HTMLIndent.SINGLE, /*key=*/ "Policy ID",
                violatedPolicyInfo.getPolicyId()));
        if (violatedPolicyInfo.getViolatedPosture() != null) {
            addPostureDetails(content, violatedPolicyInfo.getViolatedPosture());
        }
        if (violatedPolicyInfo.getViolatedPolicy() != null) {
            addPolicyDetails(content, violatedPolicyInfo.getViolatedPolicy());
        }
        content.add(ReportUtils.buildHTMLDivWithKeyValueEntry(HTMLIndent.SINGLE, /*key=*/ "NextSteps",
                violatedPolicyInfo.getNextSteps()));
    }

    private void addPostureDetails(final List<String> content, final PostureDetails violatedPosture) {
        content.add(ReportUtils.buildHTMLDivWithKeyValueEntry(HTMLIndent.SINGLE, /*key=*/ "Posture Deployment ID",
                violatedPosture.getPostureDeployment()));
        content.add(ReportUtils.buildHTMLDivWithKeyValueEntry(HTMLIndent.SINGLE, /*key=*/ "Posture Deployed at",
                violatedPosture.getPostureDeploymentTargetResource()));
        content.add(ReportUtils.buildHTMLDivWithKeyValueEntry(HTMLIndent.SINGLE, /*key=*/ "Posture",
                violatedPosture.getPosture()));
        content.add(ReportUtils.buildHTMLDivWithKeyValueEntry(HTMLIndent.SINGLE, /*key=*/ "Posture Revision Id",
                violatedPosture.getPostureRevisionId()));
        content.add(ReportUtils.buildHTMLDivWithKeyValueEntry(HTMLIndent.SINGLE, /*key=*/ "Policy Set",
                violatedPosture.getPolicySet()));
    }

    private void addPolicyDetails(final List<String> content, final PolicyDetails violatedPolicy) {
        content.add(ReportUtils.buildHTMLDivWithKeyValueEntry(HTMLIndent.SINGLE, /*key=*/ "Constraint",
                violatedPolicy.getConstraint()));
        content.add(ReportUtils.buildHTMLDivWithKeyValueEntry(HTMLIndent.SINGLE, /*key=*/ "Policy Type",
                violatedPolicy.getConstraintType()));
        content.add(ReportUtils.buildHTMLDivWithKeyValueEntry(HTMLIndent.SINGLE, /*key=*/ "Compliance Standards",
                StringUtils.join(violatedPolicy.getComplianceStandards(), ", ")));
        content.add(ReportUtils.buildHTMLDivWithKeyValueEntry(HTMLIndent.SINGLE, /*key=*/ "Description",
                violatedPolicy.getDescription()));
    }

    private void addAssetDetails(final List<String> content, Map<String, List<Violation>> violationsPerPolicy,
                                 final String policy) {
        violationsPerPolicy.get(policy).forEach(violation -> {
            content.add(ReportUtils.buildHTMLDivWithKeyAndOptionalValueEntry(HTMLIndent.SINGLE, /*key=*/ "Asset ID",
                    violation.getAssetId()));
            if (violation.getViolatedAsset() != null) {
                content.add(ReportUtils.buildHTMLDivWithKeyValueEntry(HTMLIndent.DOUBLE, /*key=*/ "Asset",
                        violation.getViolatedAsset().getAsset()));
                content.add(ReportUtils.buildHTMLDivWithKeyValueEntry(HTMLIndent.DOUBLE, /*key=*/ "Asset Type",
                        violation.getViolatedAsset().getAssetType()));
            }
        });
    }
}
