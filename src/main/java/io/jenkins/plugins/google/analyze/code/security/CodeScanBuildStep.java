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

import static org.apache.commons.lang.StringUtils.isBlank;

import com.google.common.annotations.VisibleForTesting;
import hudson.Extension;
import hudson.FilePath;
import hudson.Launcher;
import hudson.model.AbstractBuild;
import hudson.model.AbstractProject;
import hudson.model.Action;
import hudson.model.BuildListener;
import hudson.model.Descriptor;
import hudson.model.DescriptorVisibilityFilter;
import hudson.model.Item;
import hudson.tasks.BuildStepDescriptor;
import hudson.tasks.Builder;
import hudson.util.FormValidation;
import hudson.util.Secret;
import io.jenkins.plugins.google.analyze.code.security.accessor.IACValidationService;
import io.jenkins.plugins.google.analyze.code.security.commons.Config;
import io.jenkins.plugins.google.analyze.code.security.commons.CustomerMessage;
import io.jenkins.plugins.google.analyze.code.security.commons.ReportConstants;
import io.jenkins.plugins.google.analyze.code.security.exception.IACValidationException;
import io.jenkins.plugins.google.analyze.code.security.model.ConfigAggregator;
import io.jenkins.plugins.google.analyze.code.security.model.FileInfo;
import io.jenkins.plugins.google.analyze.code.security.model.IACValidationService.ValidateIACParams;
import io.jenkins.plugins.google.analyze.code.security.model.IACValidationService.response.ErrorReportRequest;
import io.jenkins.plugins.google.analyze.code.security.model.IACValidationService.response.IACScanReportRequest;
import io.jenkins.plugins.google.analyze.code.security.model.IACValidationService.response.Severity;
import io.jenkins.plugins.google.analyze.code.security.model.IACValidationService.response.Violation;
import io.jenkins.plugins.google.analyze.code.security.model.PluginConfig;
import io.jenkins.plugins.google.analyze.code.security.model.ValidationResponse;
import io.jenkins.plugins.google.analyze.code.security.reports.ExecutionFailureReportProcessor;
import io.jenkins.plugins.google.analyze.code.security.reports.IACScanReportProcessor;
import io.jenkins.plugins.google.analyze.code.security.utils.FileUtils;
import io.jenkins.plugins.google.analyze.code.security.utils.LogUtils;
import io.jenkins.plugins.google.analyze.code.security.utils.ReportUtils;
import io.jenkins.plugins.google.analyze.code.security.utils.ValidationUtils;
import io.jenkins.plugins.google.analyze.code.security.violationConfig.AssetViolationConfig;
import jakarta.annotation.Nonnull;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import jenkins.model.Jenkins;
import jenkins.tasks.SimpleBuildStep;
import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.NonNull;
import net.sf.json.JSONObject;
import org.apache.commons.lang.StringUtils;
import org.kohsuke.stapler.AncestorInPath;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.DataBoundSetter;
import org.kohsuke.stapler.QueryParameter;
import org.kohsuke.stapler.StaplerRequest;
import org.kohsuke.stapler.verb.POST;

/**
 * CodeScanBuildStep scans code file and reports vulnerabilities based on the
 * security posture configured with GCP and plugin configuration.
 */
@EqualsAndHashCode(callSuper = true)
@Data
public class CodeScanBuildStep extends Builder implements SimpleBuildStep {

    private final String orgID;

    private final String scanFileName;

    private final String scanFilePath;

    private Integer scanTimeOut;

    private Boolean failSilentlyOnPluginFailure;

    private Boolean ignoreAssetViolation;

    private List<AssetViolationConfig> assetViolationConfigs;

    private ConfigAggregator configAggregator;

    @DataBoundConstructor
    public CodeScanBuildStep(
            String orgID,
            String scanFileName,
            String filePath,
            Integer scanTimeOut,
            Boolean failSilentlyOnPluginFailure,
            Boolean ignoreAssetViolation,
            List<AssetViolationConfig> assetViolationConfigs,
            ConfigAggregator configAggregator) {
        this.orgID = orgID;
        this.scanFileName = scanFileName;
        this.scanFilePath = filePath;
        this.scanTimeOut = scanTimeOut;
        this.failSilentlyOnPluginFailure = failSilentlyOnPluginFailure;
        this.ignoreAssetViolation = ignoreAssetViolation;
        this.assetViolationConfigs = assetViolationConfigs;
        this.configAggregator = configAggregator;
    }

    /**
     * Returns descriptor for {@link CodeScanBuildStep}.
     */
    @Override
    public BuildStepDescriptorImpl getDescriptor() {
        return (BuildStepDescriptorImpl) super.getDescriptor();
    }

    /**
     * No-op hence returning build status as success for all scenarios.
     */
    @Override
    public boolean prebuild(AbstractBuild<?, ?> build, BuildListener listener) {
        return true;
    }

    /**
     * No-op hence returning empty collection.
     */
    @Override
    public @NonNull Collection<? extends Action> getProjectActions(AbstractProject<?, ?> project) {
        return Collections.emptyList();
    }

    /**
     * Invoked at build step when {@link CodeScanBuildStep} is configured at build step. Scans code for vulnerabilities
     * and publishes violation summary.
     *
     * @return build status to the build orchestrator.
     */
    @Override
    public boolean perform(AbstractBuild<?, ?> build, Launcher launcher, BuildListener listener) {
        logRequestInterception(listener);
        final Instant scanStartInstant = Instant.now();
        Instant scanEndInstant;
        String validatedFilePath = null;
        final Map<String, String> workspaceContents = new HashMap<>();
        final FilePath workspace = build.getWorkspace();
        try {
            if (workspace == null) {
                throw new RuntimeException(CustomerMessage.WORKSPACE_PATH_MISSING);
            }
            validateConfig();
            final Map<String, Secret> credMap = extractCredMap(listener);
            validateCredential(credMap, orgID);
            listener.getLogger()
                    .printf(LogUtils.info("Successfully fetched SCC Credentials corresponding to orgID : [%s]"), orgID);
            final FileInfo scanFileInfo = FileUtils.loadFileFromWorkspace(workspace, scanFileName, scanFilePath);
            validatedFilePath = scanFileInfo.getPath();
            final byte[] scanFile = scanFileInfo.getFile();
            listener.getLogger()
                    .printf(
                            LogUtils.info("Successfully fetched Scan file at the location : [%s]. Initiating scan"),
                            validatedFilePath);
            final List<Violation> violations = IACValidationService.getInstance()
                    .validateIAC(buildValidateIACParams(credMap.get(orgID), scanFile, scanStartInstant, listener));
            listener.getLogger()
                    .printf(
                            LogUtils.info("Successfully scanned file at the location : [%s], found : [%s] violations"),
                            validatedFilePath,
                            violations.size());
            scanEndInstant = Instant.now();
            IACScanReportProcessor.getInstance()
                    .processReport(
                            buildIACScanReportRequest(
                                    violations,
                                    workspace,
                                    scanStartInstant,
                                    scanEndInstant,
                                    validatedFilePath,
                                    workspaceContents),
                            listener);

            listener.getLogger()
                    .printf(
                            LogUtils.info("Successfully published violation summary at : [%s]"),
                            ReportConstants.BUILD_SUMMARY_REPORT_PATH);
            return determineBuildStatus(violations);
        } catch (Exception ex) {
            scanEndInstant = Instant.now();
            listener.getLogger().printf(LogUtils.error("Execution failed with following error : [%s]"), ex);
            Integer statusCode = 500;
            if (ex instanceof IACValidationException) {
                statusCode = ((IACValidationException) ex).getStatusCode();
            }
            if (ex instanceof IllegalArgumentException) {
                statusCode = 400;
            }

            if (workspace != null) {
                listener.getLogger()
                        .printf(
                                LogUtils.info("Successfully published plugin error report at : [%s]"),
                                ReportConstants.PLUGIN_ERROR_REPORT_PATH);
                ExecutionFailureReportProcessor.getInstance()
                        .processReport(
                                buildErrorReportRequest(
                                        ex.getMessage(),
                                        workspace,
                                        statusCode,
                                        scanStartInstant,
                                        scanEndInstant,
                                        validatedFilePath,
                                        workspaceContents),
                                listener);
            }
            return failSilentlyOnPluginFailure;
        } finally {
            try {
                build.getArtifactManager().archive(build.getWorkspace(), launcher, listener, workspaceContents);
            } catch (Exception ex) {
                listener.getLogger()
                        .printf(
                                LogUtils.error(
                                        "Encountered Error while persisting reports to artifact " + "directory : %s"),
                                ex);
            }
        }
    }

    /**
     * No-op
     */
    @Override
    public Action getProjectAction(AbstractProject<?, ?> project) {
        return null;
    }

    /**
     * Invoked by Jenkins UX to determine state of {@code this.ignoreAssetViolation}. Defaults to `true` if found to
     * be null.
     */
    public Boolean isIgnoreAssetViolation() {
        return (this.ignoreAssetViolation == null || this.ignoreAssetViolation);
    }

    /**
     * Invoked by Jenkins UX to determine state of {@code this.configAggregator}. Defaults to
     * {@code ConfigAggregator.OR}.
     */
    public Boolean isConfigAggregatorAND() {
        if (configAggregator == null) return false;
        return configAggregator.equals(ConfigAggregator.AND);
    }

    @Extension
    public static final class BuildStepDescriptorImpl extends BuildStepDescriptor<Builder> {

        /**
         * In order to load the persisted global configuration, you have to call load()
         * in the constructor.
         */
        public BuildStepDescriptorImpl() {
            this(/*load=*/ true);
        }

        private BuildStepDescriptorImpl(boolean load) {
            if (load) load();
        }

        @VisibleForTesting
        public static BuildStepDescriptorImpl newInstanceForTests() {
            return new BuildStepDescriptorImpl(false);
        }

        private List<CredentialPair> credentialPairs;

        public Collection<? extends Descriptor<?>> getAssetViolationsDescriptors() {
            return DescriptorVisibilityFilter.apply(null, Jenkins.get().getDescriptorList(AssetViolationConfig.class));
        }

        /**
         * Invoked by Jenkins UX to fetch default value for {@code this.scanTimeOut}
         */
        public Integer getDefaultScanTimeOut() {
            return Config.SCAN_TIMEOUT_DEFAULT;
        }

        @Override
        public boolean configure(StaplerRequest req, JSONObject json) throws FormException {
            credentialPairs = req.bindJSONToList(CredentialPair.class, json.get("credentialPairs"));
            save();
            return super.configure(req, json);
        }

        public List<CredentialPair> getCredentialPairs() {
            return credentialPairs;
        }

        @DataBoundSetter
        public void setCredentialPairs(List<CredentialPair> credentialPairs) {
            this.credentialPairs = credentialPairs;
        }

        @Nonnull
        @Override
        public String getDisplayName() {
            return "Perform Code Scan During Build";
        }

        @Override
        public boolean isApplicable(Class<? extends AbstractProject> jobType) {
            return true;
        }

        /**
         * Validates OrgID is non-empty and contains numeric characters only.
         *
         * @param orgID GCP organizationId.
         * @return FormValidation
         */
        @POST
        public FormValidation doCheckOrgID(@QueryParameter String orgID, @AncestorInPath Item item) {
            ValidationUtils.checkPermissions(item);
            if (!ValidationUtils.isValidOrgId(orgID)) {
                return FormValidation.error(CustomerMessage.INVALID_ORG_ID);
            }
            return FormValidation.ok();
        }

        /**
         * Validates scanFileName is not empty.
         * <p>
         * POST annotation : Added to enable CSRF protection while form validation :
         * <a href="https://www.jenkins.io/doc/developer/security/form-validation/#protecting-from-csrf">CSRF Protection</a>
         * </p>
         *
         * @param scanFileName scan file name.
         * @param item basic configuration unit in Hudson.
         * @return FormValidation
         */
        @POST
        public FormValidation doCheckScanFileName(@QueryParameter String scanFileName, @AncestorInPath Item item) {
            ValidationUtils.checkPermissions(item);
            if (isBlank(scanFileName)) {
                return FormValidation.error(CustomerMessage.INVALID_SCAN_FILE_NAME);
            }
            return FormValidation.ok();
        }

        /**
         * Validates scanTimeOut is within expected range.
         *
         * @param scanTimeOut timeout in milliseconds after which scan is aborted.
         * @param item  basic configuration unit in Hudson.
         * @return String
         */
        @POST
        public FormValidation doCheckScanTimeOut(@QueryParameter Integer scanTimeOut, @AncestorInPath Item item) {
            ValidationUtils.checkPermissions(item);
            if (!ValidationUtils.isValidScanTimeOut(scanTimeOut)) {
                return FormValidation.error(CustomerMessage.INVALID_SCAN_TIMEOUT);
            }
            return FormValidation.ok();
        }

        /**
         * Description message for IgnoreAssetViolation configuration on Jenkins UX.
         */
        public String violationHelp() {
            return "Ignore violation detected in IAC scanning";
        }
    }

    private IACScanReportRequest buildIACScanReportRequest(
            final List<Violation> violations,
            final FilePath workspacePath,
            final Instant scanStartInstant,
            final Instant scanEndInstant,
            final String validateFilePath,
            final Map<String, String> workspaceContents) {
        return IACScanReportRequest.builder()
                .violations(violations)
                .workspacePath(workspacePath)
                .scanEndTime(ReportUtils.getDateFromInstant(scanEndInstant))
                .scanStartTime(ReportUtils.getDateFromInstant(scanStartInstant))
                .validationFilePath(validateFilePath)
                .reportWritePath(ReportConstants.BUILD_SUMMARY_REPORT_PATH)
                .workspaceContents(workspaceContents)
                .build();
    }

    private Map<String, Secret> extractCredMap(final BuildListener listener) {
        BuildStepDescriptorImpl descriptor = getDescriptor();
        if (descriptor.credentialPairs == null || descriptor.credentialPairs.isEmpty()) {
            throw new IllegalArgumentException(String.format(
                    CustomerMessage.INVALID_REQUEST, String.format(CustomerMessage.CREDENTIAL_NOT_FOUND, orgID)));
        }
        final Map<String, Secret> creds = new HashMap<>();
        descriptor.credentialPairs.forEach((credentialPair) -> {
            if (creds.containsKey(credentialPair.getOrgID())) {
                throw new IllegalArgumentException(String.format(
                        CustomerMessage.INVALID_REQUEST,
                        String.format(CustomerMessage.DUPLICATE_CREDENTIALS_FOUND, orgID)));
            }
            creds.put(credentialPair.getOrgID(), credentialPair.getCredential());
        });
        return creds;
    }

    private ErrorReportRequest buildErrorReportRequest(
            final String error,
            final FilePath artifactDirPath,
            final Integer statusCode,
            final Instant scanStartInstant,
            final Instant scanEndInstant,
            final String validateFilePath,
            final Map<String, String> workspaceContents) {
        return ErrorReportRequest.builder()
                .pluginConfig(buildIACPluginConfig())
                .error(error)
                .workspacePath(artifactDirPath)
                .errorCode(String.valueOf(statusCode))
                .scanEndTime(ReportUtils.getDateFromInstant(scanEndInstant))
                .scanStartTime(ReportUtils.getDateFromInstant(scanStartInstant))
                .validationFilePath(validateFilePath)
                .reportWritePath(ReportConstants.PLUGIN_ERROR_REPORT_PATH)
                .workspaceContents(workspaceContents)
                .build();
    }

    /**
     * Determine the build status based on {@link this.ignoreAssetViolation}, {@link this.assetViolationConfigs}
     * and violations present in the response.
     *
     * @param violations violations found after code scanning.
     * @return `true` for success build status & `false` for failed build status.
     */
    private boolean determineBuildStatus(final List<Violation> violations) {
        if (ignoreAssetViolation || violations.isEmpty()) {
            return true;
        }
        final Map<Severity, Integer> violationsThresholdBySeverity = assetViolationConfigs.stream()
                .collect(Collectors.toMap(AssetViolationConfig::getSeverity, AssetViolationConfig::getCount));
        final Map<Severity, Integer> violationsBySeverity = new HashMap<>();
        violations.forEach((violation -> {
            final Severity severity = violation.getSeverity();
            violationsBySeverity.putIfAbsent(severity, 0);
            violationsBySeverity.put(severity, violationsBySeverity.get(severity) + 1);
        }));

        for (Map.Entry<Severity, Integer> entry : violationsThresholdBySeverity.entrySet()) {
            Severity severity = entry.getKey();
            Integer threshold = entry.getValue();
            // Returns `SUCCESS` build status if severity count missing in violations or severity count less than
            // threshold.
            if (configAggregator.equals(ConfigAggregator.AND)
                    && (!violationsBySeverity.containsKey(severity)
                            || (violationsBySeverity.containsKey(severity)
                                    && violationsBySeverity.get(severity) < threshold))) {
                return true;
            }
            // Returns `FAILED` build status if severity count less than threshold.
            if (configAggregator.equals(ConfigAggregator.OR)
                    && violationsBySeverity.containsKey(severity)
                    && violationsBySeverity.get(severity) >= threshold) {
                return false;
            }
        }
        return !configAggregator.equals(ConfigAggregator.AND);
    }

    private PluginConfig buildIACPluginConfig() {
        return PluginConfig.builder()
                .orgID(orgID)
                .scanFileName(scanFileName)
                .filePath(scanFilePath)
                .scanTimeOut(scanTimeOut)
                .failSilentlyOnPluginFailure(failSilentlyOnPluginFailure)
                .ignoreAssetViolation(ignoreAssetViolation)
                .assetViolationConfigs(assetViolationConfigs)
                .configAggregator(configAggregator)
                .build();
    }

    private void logRequestInterception(final BuildListener listener) {
        listener.getLogger()
                .printf(
                        LogUtils.info("Received Code Scan Request with the following configurations , "
                                + "orgID: [%s], scanFileName: [%s], scanFilePath : [%s], scanTimeOut : [%s],"
                                + "failSilentlyOnPluginFailure: [%s], ignoreAssetViolation : [%s], assetViolationConfigs : [%s] "
                                + "configAggregator : [%s]"),
                        orgID,
                        scanFileName,
                        scanFilePath,
                        scanTimeOut,
                        failSilentlyOnPluginFailure,
                        ignoreAssetViolation,
                        assetViolationConfigs,
                        configAggregator);
    }

    private void validateCredential(final Map<String, Secret> credMap, final String orgID) {
        if (!credMap.containsKey(orgID)) {
            throw new IllegalArgumentException(String.format(
                    CustomerMessage.INVALID_REQUEST, String.format(CustomerMessage.CREDENTIAL_NOT_FOUND, orgID)));
        }
        if (!ValidationUtils.isValidJSON(credMap.get(orgID).getPlainText())) {
            throw new IllegalArgumentException(String.format(
                    CustomerMessage.INVALID_REQUEST, String.format(CustomerMessage.INVALID_SCC_CREDENTIAL, orgID)));
        }
    }

    private void validateConfig() {
        final List<String> errors = new ArrayList<>();
        if (!ValidationUtils.isValidOrgId(orgID)) {
            errors.add(CustomerMessage.INVALID_ORG_ID);
        }
        if (isBlank(scanFileName)) {
            errors.add(CustomerMessage.INVALID_SCAN_FILE_NAME);
        }
        if (!ValidationUtils.isValidScanTimeOut(scanTimeOut)) {
            errors.add(CustomerMessage.INVALID_SCAN_TIMEOUT);
        }
        final ValidationResponse failureConfigValidation =
                ValidationUtils.isValidFailureConfig(ignoreAssetViolation, assetViolationConfigs);
        if (!failureConfigValidation.getIsValid()) {
            errors.addAll(failureConfigValidation.getErrors());
        }
        if (!errors.isEmpty()) {
            throw new IllegalArgumentException(
                    String.format(CustomerMessage.INVALID_CONFIG, StringUtils.join(errors, ", ")));
        }
    }

    private ValidateIACParams buildValidateIACParams(
            final Secret secret, final byte[] scanFile, final Instant scanStartInstant, final BuildListener listener) {
        return ValidateIACParams.builder()
                .orgID(orgID)
                .file(scanFile)
                .credentials(secret)
                .requestReceiveInstant(scanStartInstant)
                .pluginTimeoutInMS(scanTimeOut)
                .listener(listener)
                .build();
    }
}
