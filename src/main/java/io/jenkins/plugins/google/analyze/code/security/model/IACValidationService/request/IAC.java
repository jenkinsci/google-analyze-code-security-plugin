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

package io.jenkins.plugins.google.analyze.code.security.model.IACValidationService.request;

import com.fasterxml.jackson.annotation.JsonProperty;
import groovy.transform.ToString;
import lombok.Builder;
import lombok.EqualsAndHashCode;

/**
 * IAC models IAC Object in SCC IAC Scan Validation Request.
 */
@Builder
@ToString
@EqualsAndHashCode
public class IAC {
    private final byte[] file;

    @JsonProperty("tf_plan")
    public byte[] getFile() {
        return file;
    }
}
