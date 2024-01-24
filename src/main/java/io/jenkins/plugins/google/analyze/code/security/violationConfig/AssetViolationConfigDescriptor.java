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

package io.jenkins.plugins.google.analyze.code.security.violationConfig;

import static io.jenkins.plugins.google.analyze.code.security.commons.CustomerMessage.INVALID_VIOLATION_COUNT_CONFIGURATION;

import hudson.model.Descriptor;
import hudson.util.FormValidation;
import org.kohsuke.stapler.QueryParameter;

/**
 * AssetViolationConfigDescriptor is base class for Asset Violation Config Descriptor.
 */
public abstract class AssetViolationConfigDescriptor extends Descriptor<AssetViolationConfig> {
    /**
     * Validate Violation Count for non-null and positive integer.
     *
     * @param count violation frequency threshold for determining build failure.
     * @return FormValidation
     */
    public FormValidation doCheckCount(@QueryParameter Integer count) {
        if (count == null || count <= 0) {
            return FormValidation.error(INVALID_VIOLATION_COUNT_CONFIGURATION);
        }
        return FormValidation.ok();
    }
}
