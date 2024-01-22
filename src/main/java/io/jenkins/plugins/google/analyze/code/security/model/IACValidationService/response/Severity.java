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

package io.jenkins.plugins.google.analyze.code.security.model.IACValidationService.response;

import lombok.Getter;
import lombok.ToString;

/**
 * Severity models Severity Object present in SCC IAC Scan Validation Response.
 */
@Getter
@ToString
public enum Severity {
    SEVERITY_UNSPECIFIED(0),
    CRITICAL(1),
    HIGH(2),
    MEDIUM(3),
    LOW(4);

    private final int severity;

    Severity(int severity) {
        this.severity = severity;
    }
}
