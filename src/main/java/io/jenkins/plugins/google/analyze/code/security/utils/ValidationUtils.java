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

package io.jenkins.plugins.google.analyze.code.security.utils;

import static org.apache.commons.lang.StringUtils.isBlank;

import com.fasterxml.jackson.databind.ObjectMapper;
import hudson.model.Item;
import io.jenkins.plugins.google.analyze.code.security.commons.Config;
import io.jenkins.plugins.google.analyze.code.security.commons.CustomerMessage;
import io.jenkins.plugins.google.analyze.code.security.model.IACValidationService.response.Severity;
import io.jenkins.plugins.google.analyze.code.security.model.ValidationResponse;
import io.jenkins.plugins.google.analyze.code.security.violationConfig.AssetViolationConfig;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import jenkins.model.Jenkins;
import lombok.NonNull;
import org.apache.commons.lang.StringUtils;

/**
 * ValidationUtils provides validation helper methods.
 */
public final class ValidationUtils {

    private ValidationUtils() {}

    /***
     * Validates if the JSON is valid.
     */
    public static boolean isValidJSON(@NonNull final String json) {
        final ObjectMapper mapper = new ObjectMapper();
        try {
            mapper.readTree(json);
            return true;
        } catch (Exception ex) {
            return false;
        }
    }

    /**
     * Validates if the contents of file are valid JSON.
     */
    public static boolean isValidJSONFile(final byte[] json) {
        try {
            return isValidJSON(new String(json, StandardCharsets.UTF_8));
        } catch (Exception ex) {
            return false;
        }
    }

    /**
     * Validates if an orgID is valid.
     */
    public static boolean isValidOrgId(final String orgID) {
        return !isBlank(orgID) && orgID.matches("[0-9]+");
    }

    /**
     * Validates if scanTimeOut Config is valid.
     */
    public static boolean isValidScanTimeOut(final Integer scanTimeOut) {
        return scanTimeOut != null && scanTimeOut >= Config.SCAN_TIMEOUT_MIN && scanTimeOut <= Config.SCAN_TIMEOUT_MAX;
    }

    /**
     * Validates if failureConfig is valid.
     *
     *<p>
     * Following are conditions for a string to be a valid failureConfig:
     * 1. It must contain atleast one Severity.
     * 2. It must contain each Severity at most once
     *</p>
     *
     * @param ignoreAssetViolation build step config that determines if violations should be ignored
     * @param assetViolationConfigs threshold configs based on severity.
     */
    public static ValidationResponse isValidFailureConfig(
            final Boolean ignoreAssetViolation, final List<AssetViolationConfig> assetViolationConfigs) {
        if (ignoreAssetViolation) {
            return ValidationResponse.builder().isValid(true).build();
        }
        if (assetViolationConfigs == null || assetViolationConfigs.isEmpty()) {
            return ValidationResponse.builder()
                    .isValid(false)
                    .errors(List.of(CustomerMessage.EMPTY_ASSET_VIOLATION_CONFIG))
                    .build();
        }
        final Map<Severity, Integer> violationsThresholdConfigMap = new HashMap<>();
        assetViolationConfigs.forEach((assetViolationConfig -> {
            final Severity severity = assetViolationConfig.getSeverity();
            violationsThresholdConfigMap.putIfAbsent(severity, 0);
            violationsThresholdConfigMap.put(severity, violationsThresholdConfigMap.get(severity) + 1);
        }));
        List<String> duplicateConfigs = new ArrayList<>();
        violationsThresholdConfigMap.forEach(((violationSeverity, count) -> {
            if (count > 1) {
                duplicateConfigs.add(violationSeverity.name());
            }
        }));
        if (!duplicateConfigs.isEmpty()) {
            return ValidationResponse.builder()
                    .isValid(false)
                    .errors(List.of(String.format(
                            CustomerMessage.INVALID_SEVERITY_CONFIG,
                            StringUtils.join(duplicateConfigs, /*separator=*/ ','))))
                    .build();
        }
        return ValidationResponse.builder().isValid(true).build();
    }

    /**
     * Ensures the executing user has the permissions to be running this step.
     */
    public static void checkPermissions(final Item item) {
        if (item != null) {
            item.checkPermission(Item.CONFIGURE);
        } else {
            Jenkins.get().checkPermission(Jenkins.ADMINISTER);
        }
    }
}
