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

import static io.jenkins.plugins.google.analyze.code.security.utils.FileUtils.readResource;

import hudson.FilePath;
import hudson.model.BuildListener;
import io.jenkins.plugins.google.analyze.code.security.commons.ReportConstants;
import io.jenkins.plugins.google.analyze.code.security.model.ReportBuildRequest;
import io.jenkins.plugins.google.analyze.code.security.utils.LogUtils;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Map;

/**
 * Base Class for Report Processor.
 * Performs following operations :
 * 1) Report generation
 * 2) Report publishing.
 *
 * @param <T>
 */
public abstract class ReportProcessor<T extends ReportBuildRequest> {
    public void processReport(final T buildReportRequest, final BuildListener listener) {
        try {
            final Map<String, String> workspaceContents = buildReportRequest.getWorkspaceContents();
            final String report = generateReport(buildReportRequest);
            publishArtifact(
                    report,
                    buildReportRequest.getWorkspacePath() + buildReportRequest.getReportWritePath(),
                    buildReportRequest.getWorkspacePath());
            workspaceContents.put(buildReportRequest.getReportWritePath(), buildReportRequest.getReportWritePath());
            // write style to workspace dir
            publishArtifact(
                    readResource(ReportConstants.STYLES_CSS_PATH),
                    /*path=*/ buildReportRequest.getWorkspacePath() + ReportConstants.STYLES_CSS_PATH,
                    buildReportRequest.getWorkspacePath());
            workspaceContents.put(ReportConstants.STYLES_CSS_PATH, ReportConstants.STYLES_CSS_PATH);
        } catch (Exception ex) {
            listener.getLogger()
                    .printf(LogUtils.error("[Internal Error] Received Error while generating report : [%s]"), ex);
        }
    }

    public abstract String generateReport(final T buildReportRequest);

    private void publishArtifact(final String artifact, final String path, final FilePath workspacePath)
            throws IOException, InterruptedException {
        new FilePath(workspacePath, path).write(artifact, StandardCharsets.UTF_8.name());
    }
}
