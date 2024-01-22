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

import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.Extension;
import io.jenkins.plugins.google.analyze.code.security.model.IACValidationService.response.Severity;
import lombok.EqualsAndHashCode;
import lombok.ToString;
import org.kohsuke.stapler.DataBoundConstructor;

/**
 * HighSeverityConfig models High Severity Violation Config for Asset Violation in Jenkins UX.
 */
@EqualsAndHashCode(callSuper = true)
@ToString(callSuper = true)
public class HighSeverityConfig extends AssetViolationConfig {

    @DataBoundConstructor
    public HighSeverityConfig(final int count) {
        super(Severity.HIGH, count);
    }

    @Extension
    public static class DescriptorImpl extends AssetViolationConfigDescriptor {
        @NonNull
        @Override
        public String getDisplayName() {
            return "High Severity";
        }
    }
}
