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

package io.jenkins.plugins.google.analyze.code.security;

import static io.jenkins.plugins.google.analyze.code.security.commons.TestUtil.DUMMY_ORG_ID;

import hudson.Launcher;
import hudson.model.AbstractBuild;
import hudson.model.BuildListener;
import hudson.model.FreeStyleBuild;
import hudson.model.FreeStyleProject;
import hudson.model.Result;
import hudson.util.Secret;
import io.jenkins.cli.shaded.org.apache.commons.lang.StringUtils;
import io.jenkins.plugins.google.analyze.code.security.commons.Config;
import io.jenkins.plugins.google.analyze.code.security.commons.CustomerMessage;
import io.jenkins.plugins.google.analyze.code.security.model.ConfigAggregator;
import io.jenkins.plugins.google.analyze.code.security.violationConfig.AssetViolationConfig;
import io.jenkins.plugins.google.analyze.code.security.violationConfig.CriticalSeverityConfig;
import io.jenkins.plugins.google.analyze.code.security.violationConfig.HighSeverityConfig;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.TestBuilder;
import org.mockito.junit.MockitoJUnitRunner;

/**
 * End-to-End Test for {@link CodeScanBuildStep}.
 *
 * <p>
 * Before Invoking these test. Please Add Valid valid SCC Credentials to `DUMMY_VALID_SCC_CREDENTIAL`.
 * </p>
 */
@RunWith(MockitoJUnitRunner.class)
public class CodeScanBuildStepTest {
    private static final String DUMMY_SCAN_FILE_WITH_VULNERABILITIES_NAME = "planWithVulnerabilities.json";
    private static final String DUMMY_SCAN_FILE_WITHOUT_VULNERABILITIES_NAME = "planWithoutVulnerabilities.json";
    private static final Boolean IGNORE_ASSET_VIOLATION_TRUE = true;
    private static final Boolean IGNORE_ASSET_VIOLATION_FALSE = false;
    private static final Boolean FAIL_SILENTLY_ON_PLUGIN_FAILURE_FALSE = false;
    private static final List<AssetViolationConfig> DUMMY_ASSET_VIOLATION_CONFIG =
            List.of(new CriticalSeverityConfig(/*count=*/ 1), new HighSeverityConfig(/*count=*/ 1));

    private static final String DUMMY_INVALID_ORG_ID = "cscscs";

    // Please add service account credentials before invoking the E2E test.
    private static final String DUMMY_VALID_SCC_CREDENTIAL = "";

    private static final String DUMMY_MALFORMED_SCC_CREDENTIALS = "{\n" + "  \"type\": \"service_account\",\n"
            + "  \"project_id\": \"dummy-project\",\n"
            + "  \"private_key_id\": \"dummy\",\n"
            + "  \"private_key\": \"-----BEGIN PRIVATE KEY-----\\"
            + "\\n-----END PRIVATE KEY-----\\n\",\n"
            + "  \"client_email\": \"random\",\n"
            + "  \"client_id\": \"random\",\n"
            + "  \"auth_uri\": \"random\",\n"
            + "  \"token_uri\": \"random\",\n"
            + "  \"auth_provider_x509_cert_url\": \"random\",\n"
            + "  \"client_x509_cert_url\": \"random\",\n"
            + "  \"universe_domain\": \"googleapis.com\"\n"
            + "}";

    @Rule
    public final JenkinsRule jenkinsRule = new JenkinsRule();

    @Before
    public void setup() {}

    @Test
    public void
            codeScanBuildStep_scanFileWithVulnerabilitiesIgnoreAssetViolationFalse_SCCReturnsCriticalViolationsBuildStatusFail()
                    throws Exception {
        // skip test if credentials are not found.
        org.junit.Assume.assumeTrue(!DUMMY_VALID_SCC_CREDENTIAL.isBlank());

        FreeStyleProject p = jenkinsRule.createFreeStyleProject();
        p.getBuildersList().add(addScanFileToWorkspace(DUMMY_SCAN_FILE_WITH_VULNERABILITIES_NAME));
        final CodeScanBuildStep codeScanBuildStep = new CodeScanBuildStep(
                DUMMY_ORG_ID,
                DUMMY_SCAN_FILE_WITH_VULNERABILITIES_NAME,
                /*filePath=*/ null,
                Config.SCAN_TIMEOUT_DEFAULT,
                FAIL_SILENTLY_ON_PLUGIN_FAILURE_FALSE,
                IGNORE_ASSET_VIOLATION_FALSE,
                DUMMY_ASSET_VIOLATION_CONFIG,
                ConfigAggregator.OR);
        codeScanBuildStep
                .getDescriptor()
                .setCredentialPairs(
                        List.of(new CredentialPair(DUMMY_ORG_ID, Secret.fromString(DUMMY_VALID_SCC_CREDENTIAL))));
        p.getBuildersList().add(codeScanBuildStep);

        FreeStyleBuild build = p.scheduleBuild2(/*quietPeriod=*/ 0).get();

        jenkinsRule.assertBuildStatus(Result.FAILURE, build);
        jenkinsRule.assertLogContains(/*substring=*/ "Received Code Scan Request", build);
        jenkinsRule.assertLogContains(/*substring=*/ "Successfully fetched SCC Credentials", build);
        jenkinsRule.assertLogContains(/*substring=*/ "Successfully fetched Scan file", build);
        jenkinsRule.assertLogContains(
                /*substring=*/ "Invoking IAC Validating Service for validating  Scan file", build);
        jenkinsRule.assertLogContains(/*substring=*/ "Requesting Validation Service Polling Endpoint", build);
        jenkinsRule.assertLogContains(/*substring=*/ "Received Validation Service Polling Endpoint", build);
        jenkinsRule.assertLogContains(/*substring=*/ "Polling Validation Service Endpoint", build);
        jenkinsRule.assertLogContains(/*substring=*/ "Received Response from Validation Service Endpoint", build);
        jenkinsRule.assertLogContains(
                /*substring=*/ "Successfully scanned file at the location : "
                        + "[test0/planWithVulnerabilities.json], found : [2] violations",
                build);
        jenkinsRule.assertLogContains(/*substring=*/ "Successfully published violation summary", build);
    }

    @Test
    public void
            codeScanBuildStep_scanFileWithVulnerabilitiesIgnoreAssetViolationTrue_SCCReturnsCriticalViolationsBuildStatusSuccess()
                    throws Exception {
        // skip test if credentials are not found.
        org.junit.Assume.assumeTrue(!DUMMY_VALID_SCC_CREDENTIAL.isBlank());

        FreeStyleProject p = jenkinsRule.createFreeStyleProject();
        p.getBuildersList().add(addScanFileToWorkspace(DUMMY_SCAN_FILE_WITH_VULNERABILITIES_NAME));
        final CodeScanBuildStep codeScanBuildStep = new CodeScanBuildStep(
                DUMMY_ORG_ID,
                DUMMY_SCAN_FILE_WITH_VULNERABILITIES_NAME,
                /*filePath=*/ null,
                Config.SCAN_TIMEOUT_DEFAULT,
                FAIL_SILENTLY_ON_PLUGIN_FAILURE_FALSE,
                IGNORE_ASSET_VIOLATION_TRUE,
                DUMMY_ASSET_VIOLATION_CONFIG,
                ConfigAggregator.OR);
        codeScanBuildStep
                .getDescriptor()
                .setCredentialPairs(
                        List.of(new CredentialPair(DUMMY_ORG_ID, Secret.fromString(DUMMY_VALID_SCC_CREDENTIAL))));
        p.getBuildersList().add(codeScanBuildStep);

        FreeStyleBuild build = p.scheduleBuild2(/*quietPeriod=*/ 0).get();

        jenkinsRule.assertBuildStatusSuccess(build);
        jenkinsRule.assertLogContains(/*substring=*/ "Received Code Scan Request", build);
        jenkinsRule.assertLogContains(/*substring=*/ "Successfully fetched SCC Credentials", build);
        jenkinsRule.assertLogContains(/*substring=*/ "Successfully fetched Scan file", build);
        jenkinsRule.assertLogContains(
                /*substring=*/ "Invoking IAC Validating Service for validating  Scan file", build);
        jenkinsRule.assertLogContains(/*substring=*/ "Requesting Validation Service Polling Endpoint", build);
        jenkinsRule.assertLogContains(/*substring=*/ "Received Validation Service Polling Endpoint", build);
        jenkinsRule.assertLogContains(/*substring=*/ "Polling Validation Service Endpoint", build);
        jenkinsRule.assertLogContains(/*substring=*/ "Received Response from Validation Service Endpoint", build);
        jenkinsRule.assertLogContains(
                /*substring=*/ "Successfully scanned file at the location : "
                        + "[test0/planWithVulnerabilities.json], found : [2] violations",
                build);
        jenkinsRule.assertLogContains(/*substring=*/ "Successfully published violation summary", build);
    }

    @Test
    public void codeScanBuildStep_scanFileWithoutVulnerabilities_SCCReturnsEmptyViolationsBuildStatusSuccess()
            throws Exception {
        // skip test if credentials are not found.
        org.junit.Assume.assumeTrue(!DUMMY_VALID_SCC_CREDENTIAL.isBlank());

        FreeStyleProject p = jenkinsRule.createFreeStyleProject();
        p.getBuildersList().add(addScanFileToWorkspace(DUMMY_SCAN_FILE_WITHOUT_VULNERABILITIES_NAME));
        final CodeScanBuildStep codeScanBuildStep = new CodeScanBuildStep(
                DUMMY_ORG_ID,
                DUMMY_SCAN_FILE_WITHOUT_VULNERABILITIES_NAME,
                /*filePath=*/ null,
                Config.SCAN_TIMEOUT_DEFAULT,
                FAIL_SILENTLY_ON_PLUGIN_FAILURE_FALSE,
                IGNORE_ASSET_VIOLATION_FALSE,
                DUMMY_ASSET_VIOLATION_CONFIG,
                ConfigAggregator.OR);
        codeScanBuildStep
                .getDescriptor()
                .setCredentialPairs(
                        List.of(new CredentialPair(DUMMY_ORG_ID, Secret.fromString(DUMMY_VALID_SCC_CREDENTIAL))));
        p.getBuildersList().add(codeScanBuildStep);

        FreeStyleBuild build = p.scheduleBuild2(/*quietPeriod=*/ 0).get();

        jenkinsRule.assertBuildStatusSuccess(build);
        jenkinsRule.assertLogContains(/*substring=*/ "Received Code Scan Request", build);
        jenkinsRule.assertLogContains(/*substring=*/ "Successfully fetched SCC Credentials", build);
        jenkinsRule.assertLogContains(/*substring=*/ "Successfully fetched Scan file", build);
        jenkinsRule.assertLogContains(
                /*substring=*/ "Invoking IAC Validating Service for validating  Scan file", build);
        jenkinsRule.assertLogContains(/*substring=*/ "Requesting Validation Service Polling Endpoint", build);
        jenkinsRule.assertLogContains(/*substring=*/ "Received Validation Service Polling Endpoint", build);
        jenkinsRule.assertLogContains(/*substring=*/ "Polling Validation Service Endpoint", build);
        jenkinsRule.assertLogContains(/*substring=*/ "Received Response from Validation Service Endpoint", build);
        jenkinsRule.assertLogContains(
                /*substring=*/ "Successfully scanned file at the location : "
                        + "[test0/planWithoutVulnerabilities.json], found : [0] violations",
                build);
        jenkinsRule.assertLogContains(/*substring=*/ "Successfully published violation summary", build);
    }

    @Test
    public void codeScanBuildStep_invalidConfigMultipleErrorsFailSilentlyFalse_failedBuildStatus() throws Exception {
        FreeStyleProject p = jenkinsRule.createFreeStyleProject();
        final CodeScanBuildStep codeScanBuildStep = new CodeScanBuildStep(
                DUMMY_INVALID_ORG_ID,
                StringUtils.EMPTY,
                /*filePath=*/ null,
                (Config.SCAN_TIMEOUT_MIN - 10),
                FAIL_SILENTLY_ON_PLUGIN_FAILURE_FALSE,
                IGNORE_ASSET_VIOLATION_FALSE,
                List.of(new HighSeverityConfig(/*count=*/ 1), new HighSeverityConfig(/*count=*/ 2)),
                ConfigAggregator.OR);
        codeScanBuildStep
                .getDescriptor()
                .setCredentialPairs(
                        List.of(new CredentialPair(DUMMY_ORG_ID, Secret.fromString(DUMMY_VALID_SCC_CREDENTIAL))));
        p.getBuildersList().add(codeScanBuildStep);

        FreeStyleBuild build = p.scheduleBuild2(/*quietPeriod=*/ 0).get();

        jenkinsRule.assertBuildStatus(Result.FAILURE, build);
        jenkinsRule.assertLogContains(/*substring=*/ "Received Code Scan Request", build);
        jenkinsRule.assertLogContains(CustomerMessage.INVALID_ORG_ID, build);
        jenkinsRule.assertLogContains(CustomerMessage.INVALID_SCAN_FILE_NAME, build);
        jenkinsRule.assertLogContains(CustomerMessage.INVALID_SCAN_TIMEOUT, build);
        jenkinsRule.assertLogContains(String.format(CustomerMessage.INVALID_SEVERITY_CONFIG, "HIGH"), build);
        jenkinsRule.assertLogContains(/*substring=*/ "Successfully published plugin error report", build);
    }

    @Test
    public void codeScanBuildStep_invalidOrgIDFailSilentlyTrue_SuccessBuildStatus() throws Exception {
        FreeStyleProject p = jenkinsRule.createFreeStyleProject();
        p.getBuildersList().add(addScanFileToWorkspace(DUMMY_SCAN_FILE_WITHOUT_VULNERABILITIES_NAME));
        final CodeScanBuildStep codeScanBuildStep = new CodeScanBuildStep(
                DUMMY_INVALID_ORG_ID,
                DUMMY_SCAN_FILE_WITHOUT_VULNERABILITIES_NAME,
                /*filePath=*/ null,
                Config.SCAN_TIMEOUT_DEFAULT,
                /*failSilentlyOnPluginFailure=*/ true,
                IGNORE_ASSET_VIOLATION_FALSE,
                DUMMY_ASSET_VIOLATION_CONFIG,
                ConfigAggregator.OR);
        codeScanBuildStep
                .getDescriptor()
                .setCredentialPairs(
                        List.of(new CredentialPair(DUMMY_ORG_ID, Secret.fromString(DUMMY_VALID_SCC_CREDENTIAL))));
        p.getBuildersList().add(codeScanBuildStep);

        FreeStyleBuild build = p.scheduleBuild2(/*quietPeriod=*/ 0).get();

        jenkinsRule.assertBuildStatusSuccess(build);
        jenkinsRule.assertLogContains(/*substring=*/ "Received Code Scan Request", build);
        jenkinsRule.assertLogContains(CustomerMessage.INVALID_ORG_ID, build);
        jenkinsRule.assertLogContains(/*substring=*/ "Successfully published plugin error report", build);
    }

    @Test
    public void codeScanBuildStep_scanFileNotFound_failedBuildStatus() throws Exception {
        FreeStyleProject p = jenkinsRule.createFreeStyleProject();
        final CodeScanBuildStep codeScanBuildStep = new CodeScanBuildStep(
                DUMMY_ORG_ID,
                DUMMY_SCAN_FILE_WITH_VULNERABILITIES_NAME,
                /*filePath=*/ null,
                Config.SCAN_TIMEOUT_DEFAULT,
                FAIL_SILENTLY_ON_PLUGIN_FAILURE_FALSE,
                IGNORE_ASSET_VIOLATION_FALSE,
                DUMMY_ASSET_VIOLATION_CONFIG,
                ConfigAggregator.OR);
        codeScanBuildStep
                .getDescriptor()
                .setCredentialPairs(
                        List.of(new CredentialPair(DUMMY_ORG_ID, Secret.fromString(DUMMY_VALID_SCC_CREDENTIAL))));
        p.getBuildersList().add(codeScanBuildStep);

        FreeStyleBuild build = p.scheduleBuild2(/*quietPeriod=*/ 0).get();

        jenkinsRule.assertBuildStatus(Result.FAILURE, build);
        jenkinsRule.assertLogContains(/*substring=*/ "Received Code Scan Request", build);
        jenkinsRule.assertLogContains(CustomerMessage.FILE_NOT_FOUND, build);
        jenkinsRule.assertLogContains(/*substring=*/ "Successfully published plugin error report", build);
    }

    @Test
    public void codeScanBuildStep_credentialsNotFound_failedBuildStatus() throws Exception {
        FreeStyleProject p = jenkinsRule.createFreeStyleProject();
        p.getBuildersList().add(addScanFileToWorkspace(DUMMY_SCAN_FILE_WITH_VULNERABILITIES_NAME));
        final CodeScanBuildStep codeScanBuildStep = new CodeScanBuildStep(
                DUMMY_ORG_ID,
                DUMMY_SCAN_FILE_WITH_VULNERABILITIES_NAME,
                /*filePath=*/ null,
                Config.SCAN_TIMEOUT_DEFAULT,
                FAIL_SILENTLY_ON_PLUGIN_FAILURE_FALSE,
                IGNORE_ASSET_VIOLATION_FALSE,
                List.of(new CriticalSeverityConfig(/*count=*/ 1), new HighSeverityConfig(/*count=*/ 1)),
                ConfigAggregator.OR);
        p.getBuildersList().add(codeScanBuildStep);

        FreeStyleBuild build = p.scheduleBuild2(/*quietPeriod=*/ 0).get();

        jenkinsRule.assertBuildStatus(Result.FAILURE, build);
        jenkinsRule.assertLogContains(/*substring=*/ "Received Code Scan Request", build);
        jenkinsRule.assertLogContains(String.format(CustomerMessage.CREDENTIAL_NOT_FOUND, DUMMY_ORG_ID), build);
        jenkinsRule.assertLogContains(/*substring=*/ "Successfully published plugin error report", build);
    }

    @Test
    public void codeScanBuildStep_malformedCredentials_failedBuildStatus() throws Exception {
        FreeStyleProject p = jenkinsRule.createFreeStyleProject();
        p.getBuildersList().add(addScanFileToWorkspace(DUMMY_SCAN_FILE_WITHOUT_VULNERABILITIES_NAME));
        final CodeScanBuildStep codeScanBuildStep = new CodeScanBuildStep(
                DUMMY_ORG_ID,
                DUMMY_SCAN_FILE_WITHOUT_VULNERABILITIES_NAME,
                /*filePath=*/ null,
                Config.SCAN_TIMEOUT_DEFAULT,
                FAIL_SILENTLY_ON_PLUGIN_FAILURE_FALSE,
                IGNORE_ASSET_VIOLATION_FALSE,
                DUMMY_ASSET_VIOLATION_CONFIG,
                ConfigAggregator.OR);
        codeScanBuildStep
                .getDescriptor()
                .setCredentialPairs(
                        List.of(new CredentialPair(DUMMY_ORG_ID, Secret.fromString(DUMMY_MALFORMED_SCC_CREDENTIALS))));
        p.getBuildersList().add(codeScanBuildStep);

        FreeStyleBuild build = p.scheduleBuild2(/*quietPeriod=*/ 0).get();

        jenkinsRule.assertBuildStatus(Result.FAILURE, build);
        jenkinsRule.assertLogContains(/*substring=*/ "Received Code Scan Request", build);
        jenkinsRule.assertLogContains(/*substring=*/ "Successfully fetched SCC Credentials", build);
        jenkinsRule.assertLogContains(/*substring=*/ "Successfully fetched Scan file", build);
        jenkinsRule.assertLogContains(
                /*substring=*/ "Invoking IAC Validating Service for validating  Scan file", build);
        jenkinsRule.assertLogContains(/*substring=*/ "statusCode=400", build);
        jenkinsRule.assertLogContains(/*substring=*/ CustomerMessage.MALFORMED_SCC_CREDENTIAL, build);
        jenkinsRule.assertLogContains(/*substring=*/ "Successfully published plugin error report", build);
    }

    @Test
    public void codeScanBuildStep_CredentialsWithOutEnoughPermissionForOrgId_SCCThrowsForbiddenCausingExecutionFailure()
            throws Exception {
        // skip test if credentials are not found.
        org.junit.Assume.assumeTrue(!DUMMY_VALID_SCC_CREDENTIAL.isBlank());

        final String orgID = "77783840325";
        FreeStyleProject p = jenkinsRule.createFreeStyleProject();
        p.getBuildersList().add(addScanFileToWorkspace(DUMMY_SCAN_FILE_WITH_VULNERABILITIES_NAME));
        final CodeScanBuildStep codeScanBuildStep = new CodeScanBuildStep(
                orgID,
                DUMMY_SCAN_FILE_WITH_VULNERABILITIES_NAME,
                /*filePath=*/ null,
                Config.SCAN_TIMEOUT_DEFAULT,
                FAIL_SILENTLY_ON_PLUGIN_FAILURE_FALSE,
                IGNORE_ASSET_VIOLATION_FALSE,
                DUMMY_ASSET_VIOLATION_CONFIG,
                ConfigAggregator.OR);
        codeScanBuildStep
                .getDescriptor()
                .setCredentialPairs(List.of(new CredentialPair(orgID, Secret.fromString(DUMMY_VALID_SCC_CREDENTIAL))));
        p.getBuildersList().add(codeScanBuildStep);

        FreeStyleBuild build = p.scheduleBuild2(/*quietPeriod=*/ 0).get();

        jenkinsRule.assertBuildStatus(Result.FAILURE, build);
        jenkinsRule.assertLogContains(/*substring=*/ "Received Code Scan Request", build);
        jenkinsRule.assertLogContains(/*substring=*/ "Successfully fetched SCC Credentials", build);
        jenkinsRule.assertLogContains(/*substring=*/ "Successfully fetched Scan file", build);
        jenkinsRule.assertLogContains(/*substring=*/ "Requesting Validation Service Polling Endpoint", build);
        jenkinsRule.assertLogContains(/*substring=*/ "statusCode=403", build);
        jenkinsRule.assertLogContains(/*substring=*/ "Successfully published plugin error report", build);
    }

    @Test
    public void codeScanBuildStep_malFormedScanFile_SCCThrowsInvalidRequestCausingExecutionFailure() throws Exception {
        // skip test if credentials are not found.
        org.junit.Assume.assumeTrue(!DUMMY_VALID_SCC_CREDENTIAL.isBlank());

        FreeStyleProject p = jenkinsRule.createFreeStyleProject();
        p.getBuildersList().add(addScanFileToWorkspace(/*scanFileName=*/ "malformedPlanFile.json"));
        final CodeScanBuildStep codeScanBuildStep = new CodeScanBuildStep(
                DUMMY_ORG_ID,
                /*scanFileName=*/ "malformedPlanFile.json",
                /*filePath=*/ null,
                Config.SCAN_TIMEOUT_DEFAULT,
                FAIL_SILENTLY_ON_PLUGIN_FAILURE_FALSE,
                IGNORE_ASSET_VIOLATION_FALSE,
                DUMMY_ASSET_VIOLATION_CONFIG,
                ConfigAggregator.OR);
        codeScanBuildStep
                .getDescriptor()
                .setCredentialPairs(
                        List.of(new CredentialPair(DUMMY_ORG_ID, Secret.fromString(DUMMY_VALID_SCC_CREDENTIAL))));
        p.getBuildersList().add(codeScanBuildStep);

        FreeStyleBuild build = p.scheduleBuild2(/*quietPeriod=*/ 0).get();

        jenkinsRule.assertBuildStatus(Result.FAILURE, build);
        jenkinsRule.assertLogContains(/*substring=*/ "Received Code Scan Request", build);
        jenkinsRule.assertLogContains(/*substring=*/ "Successfully fetched SCC Credentials", build);
        jenkinsRule.assertLogContains(/*substring=*/ "Successfully fetched Scan file", build);
        jenkinsRule.assertLogContains(/*substring=*/ "Requesting Validation Service Polling Endpoint", build);
        jenkinsRule.assertLogContains(/*substring=*/ "statusCode=400", build);
        jenkinsRule.assertLogContains(/*substring=*/ "Successfully published plugin error report", build);
    }

    @Test
    public void codeScanBuildStep_invalidAssetViolationZeroThresholdForMediumSeverity_failedBuildStatus()
            throws Exception {
        FreeStyleProject p = jenkinsRule.createFreeStyleProject();
        p.getBuildersList().add(addScanFileToWorkspace(DUMMY_SCAN_FILE_WITHOUT_VULNERABILITIES_NAME));
        final CodeScanBuildStep codeScanBuildStep = new CodeScanBuildStep(
                DUMMY_ORG_ID,
                DUMMY_SCAN_FILE_WITHOUT_VULNERABILITIES_NAME,
                /*filePath=*/ null,
                Config.SCAN_TIMEOUT_DEFAULT,
                FAIL_SILENTLY_ON_PLUGIN_FAILURE_FALSE,
                IGNORE_ASSET_VIOLATION_FALSE,
                List.of(new CriticalSeverityConfig(/*count=*/ 1), new HighSeverityConfig(/*count=*/ 0)),
                ConfigAggregator.OR);
        codeScanBuildStep
                .getDescriptor()
                .setCredentialPairs(
                        List.of(new CredentialPair(DUMMY_ORG_ID, Secret.fromString(DUMMY_VALID_SCC_CREDENTIAL))));
        p.getBuildersList().add(codeScanBuildStep);

        FreeStyleBuild build = p.scheduleBuild2(/*quietPeriod=*/ 0).get();

        jenkinsRule.assertBuildStatus(Result.FAILURE, build);
        jenkinsRule.assertLogContains(/*substring=*/ "Received Code Scan Request", build);
        jenkinsRule.assertLogContains(String.format(CustomerMessage.INVALID_SEVERITY_THRESHOLD, "HIGH", 0), build);
        jenkinsRule.assertLogContains(/*substring=*/ "Successfully published plugin error report", build);
    }

    @Test
    public void codeScanBuildStep_invalidAssetViolationEmptyConfigs_failedBuildStatus() throws Exception {
        FreeStyleProject p = jenkinsRule.createFreeStyleProject();
        p.getBuildersList().add(addScanFileToWorkspace(DUMMY_SCAN_FILE_WITHOUT_VULNERABILITIES_NAME));
        final CodeScanBuildStep codeScanBuildStep = new CodeScanBuildStep(
                DUMMY_ORG_ID,
                DUMMY_SCAN_FILE_WITHOUT_VULNERABILITIES_NAME,
                /*filePath=*/ null,
                Config.SCAN_TIMEOUT_DEFAULT,
                FAIL_SILENTLY_ON_PLUGIN_FAILURE_FALSE,
                IGNORE_ASSET_VIOLATION_FALSE,
                new ArrayList<>(),
                ConfigAggregator.OR);
        codeScanBuildStep
                .getDescriptor()
                .setCredentialPairs(
                        List.of(new CredentialPair(DUMMY_ORG_ID, Secret.fromString(DUMMY_VALID_SCC_CREDENTIAL))));
        p.getBuildersList().add(codeScanBuildStep);

        FreeStyleBuild build = p.scheduleBuild2(/*quietPeriod=*/ 0).get();

        jenkinsRule.assertBuildStatus(Result.FAILURE, build);
        jenkinsRule.assertLogContains(/*substring=*/ "Received Code Scan Request", build);
        jenkinsRule.assertLogContains(CustomerMessage.EMPTY_ASSET_VIOLATION_CONFIG, build);
        jenkinsRule.assertLogContains(/*substring=*/ "Successfully published plugin error report", build);
    }

    @Test
    public void codeScanBuildStep_invalidAssetViolationDuplicateConfigs_failedBuildStatus() throws Exception {
        FreeStyleProject p = jenkinsRule.createFreeStyleProject();
        p.getBuildersList().add(addScanFileToWorkspace(DUMMY_SCAN_FILE_WITHOUT_VULNERABILITIES_NAME));
        final CodeScanBuildStep codeScanBuildStep = new CodeScanBuildStep(
                DUMMY_ORG_ID,
                DUMMY_SCAN_FILE_WITHOUT_VULNERABILITIES_NAME,
                /*filePath=*/ null,
                Config.SCAN_TIMEOUT_DEFAULT,
                FAIL_SILENTLY_ON_PLUGIN_FAILURE_FALSE,
                IGNORE_ASSET_VIOLATION_FALSE,
                List.of(new HighSeverityConfig(/*count=*/ 1), new HighSeverityConfig(/*count=*/ 2)),
                ConfigAggregator.OR);
        codeScanBuildStep
                .getDescriptor()
                .setCredentialPairs(
                        List.of(new CredentialPair(DUMMY_ORG_ID, Secret.fromString(DUMMY_VALID_SCC_CREDENTIAL))));
        p.getBuildersList().add(codeScanBuildStep);

        FreeStyleBuild build = p.scheduleBuild2(/*quietPeriod=*/ 0).get();

        jenkinsRule.assertBuildStatus(Result.FAILURE, build);
        jenkinsRule.assertLogContains(/*substring=*/ "Received Code Scan Request", build);
        jenkinsRule.assertLogContains(String.format(CustomerMessage.INVALID_SEVERITY_CONFIG, "HIGH"), build);
        jenkinsRule.assertLogContains(/*substring=*/ "Successfully published plugin error report", build);
    }

    @Test
    public void codeScanBuildStep_nestedScaFile_successfullyReadScanFile() throws Exception {
        FreeStyleProject p = jenkinsRule.createFreeStyleProject();
        final String filePath = "nestedScanFile/planFile.json";
        p.getBuildersList().add(addScanFileToWorkspace(/*scanFileName*/ filePath));
        final CodeScanBuildStep codeScanBuildStep = new CodeScanBuildStep(
                DUMMY_ORG_ID,
                /*scanFileName*/ "planFile.json",
                /*filePath=*/ null,
                Config.SCAN_TIMEOUT_DEFAULT,
                FAIL_SILENTLY_ON_PLUGIN_FAILURE_FALSE,
                IGNORE_ASSET_VIOLATION_FALSE,
                DUMMY_ASSET_VIOLATION_CONFIG,
                ConfigAggregator.OR);
        codeScanBuildStep
                .getDescriptor()
                .setCredentialPairs(
                        List.of(new CredentialPair(DUMMY_ORG_ID, Secret.fromString(DUMMY_VALID_SCC_CREDENTIAL))));
        p.getBuildersList().add(codeScanBuildStep);

        FreeStyleBuild build = p.scheduleBuild2(/*quietPeriod=*/ 0).get();

        jenkinsRule.assertLogContains(/*substring=*/ "Received Code Scan Request", build);
        jenkinsRule.assertLogContains(/*substring=*/ "Successfully fetched SCC Credentials", build);
        jenkinsRule.assertLogContains(
                /*substring=*/ String.format(
                        "Successfully fetched Scan file at the " + "location : [%s]", "test0/" + filePath),
                build);
    }

    private TestBuilder addScanFileToWorkspace(final String scanFileName) {
        return new TestBuilder() {
            @Override
            public boolean perform(AbstractBuild<?, ?> build, Launcher launcher, BuildListener listener)
                    throws InterruptedException, IOException {
                Objects.requireNonNull(build.getWorkspace())
                        .child(scanFileName)
                        .copyFrom(Objects.requireNonNull(getClass().getResource(/*name=*/ "/" + scanFileName)));
                return true;
            }
        };
    }
}
