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

import io.jenkins.plugins.google.analyze.code.security.commons.Config;
import java.time.Instant;

/**
 * LogUtils provides utility methods for adding boilerplate logic to log statements.
 */
public final class LogUtils {

    private LogUtils() {}

    public static String info(final String message) {
        return String.format("%s[INFO]%s%n", log(), message);
    }

    public static String warn(final String message) {
        return String.format("%s[WARN]%s%n", log(), message);
    }

    public static String error(final String message) {
        return String.format("%s[ERROR]%s%n", log(), message);
    }

    private static String log() {
        return String.format("[%s][%s]", ReportUtils.getDateFromInstant(Instant.now()), Config.PLUGIN_NAME);
    }
}
