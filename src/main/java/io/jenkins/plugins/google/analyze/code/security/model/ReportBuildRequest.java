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

package io.jenkins.plugins.google.analyze.code.security.model;

import hudson.FilePath;
import lombok.Data;
import lombok.NonNull;
import lombok.experimental.SuperBuilder;
import java.util.Map;

/**
 * ReportBuildRequest encapsulates arguments for building report request.
 */
@Data
@SuperBuilder
public class ReportBuildRequest {
    private String validationFilePath;
    @NonNull
    private FilePath workspacePath;
    @NonNull
    private String reportWritePath;
    @NonNull
    private String scanStartTime;
    @NonNull
    private String scanEndTime;
    @NonNull
    private Map<String, String> workspaceContents;
}
