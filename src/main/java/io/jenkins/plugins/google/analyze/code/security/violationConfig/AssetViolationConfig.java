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

import hudson.ExtensionPoint;
import hudson.model.AbstractDescribableImpl;
import io.jenkins.plugins.google.analyze.code.security.model.IACValidationService.response.Severity;
import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.ToString;
import org.kohsuke.stapler.DataBoundSetter;
import java.io.Serializable;

/**
 * AssetViolationConfig is base class for violation configs of different severity classes.
 */
@EqualsAndHashCode(callSuper = true)
@Data
@ToString
public abstract class AssetViolationConfig extends AbstractDescribableImpl<AssetViolationConfig>
        implements Serializable, ExtensionPoint {

    protected Severity severity;

    protected int count;

    public AssetViolationConfig(final Severity severity, final int count) {
        this.severity = severity;
        this.count = count;
    }

    @DataBoundSetter
    public void setCount(int count) {
        this.count = count;
    }
}
