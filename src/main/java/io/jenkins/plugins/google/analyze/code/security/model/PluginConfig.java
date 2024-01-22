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

import io.jenkins.plugins.google.analyze.code.security.violationConfig.AssetViolationConfig;
import lombok.Builder;
import lombok.Data;
import lombok.NonNull;
import java.util.List;

/**
 * PluginConfig encapsulates plugin config arguments.
 */
@Data
@Builder
public class PluginConfig {
    private final String orgID;
    private final String scanFileName;
    @NonNull
    private final Integer scanTimeOut;
    @NonNull
    private final Boolean ignoreAssetViolation;
    @NonNull
    private final Boolean failSilentlyOnPluginFailure;
    private final String filePath;
    private final List<AssetViolationConfig> assetViolationConfigs;
    @NonNull
    private final ConfigAggregator configAggregator;
}
