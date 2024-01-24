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

import io.jenkins.plugins.google.analyze.code.security.commons.ReportConstants;
import io.jenkins.plugins.google.analyze.code.security.model.HTMLIndent;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;
import org.apache.commons.lang.StringUtils;

/**
 * ReportUtils provides utility methods for building report.
 */
public final class ReportUtils {

    private ReportUtils() {}

    /**
     * Returns HTML formatted Div Block.
     *
     * <p>
     * Skips HTML Div Creation if key is missing and returns empty string.
     * Intentionally fail silently by returning empty string and not throw error in order to ensure
     * entire report is not impacted because of a missing attribute.
     * </p>
     *
     * @param indent spacing related styling.
     * @param key key attribute in the div.
     * @param value value attribute in the div.
     */
    public static String buildHTMLDivWithKeyAndOptionalValueEntry(
            final HTMLIndent indent, final String key, final String value) {
        if (isBlank(key)) {
            return StringUtils.EMPTY;
        }
        List<String> content = new ArrayList<>();
        content.add(ReportConstants.INDENT_CLASS_DIV.replace(
                "$INDENT_LEVEL_PLACEHOLDER$", indent.getIndent().toString()));
        content.add(ReportConstants.KEY_CLASS_DIV.replace(/*target=*/ "$KEY_PLACEHOLDER$", key));

        if (!isBlank(value)) {
            content.add(ReportConstants.VALUE_CLASS_DIV.replace(/*target=*/ "$VALUE_PLACEHOLDER$", value));
        }
        content.add(ReportConstants.DIV_CLOSE);
        return StringUtils.join(content, /*separator=*/ "\n");
    }

    /**
     * Returns HTML formatted Div Block.
     *
     * <p>
     * Skips HTML Div Creation if value is missing and returns empty string.
     * We are intentionally failing silently by returning empty string and not throwing error as
     * we do not want to affect entire report because of a missing attribute.
     * </p>
     *
     * @param indent spacing related styling.
     * @param key key attribute in the div.
     * @param value value attribute in the div.
     */
    public static String buildHTMLDivWithKeyValueEntry(final HTMLIndent indent, final String key, final String value) {
        if (isBlank(value)) {
            return StringUtils.EMPTY;
        }
        return buildHTMLDivWithKeyAndOptionalValueEntry(indent, key, value);
    }

    /**
     * Extracts {@link java.util.Date} from {@link Instant}.
     *
     * @param instant instantaneous point on the time-line.
     */
    public static String getDateFromInstant(final Instant instant) {
        final DateTimeFormatter formatter =
                DateTimeFormatter.ofPattern("dd MM yyyy HH:mm:ss").withZone(ZoneId.from(ZoneOffset.UTC));
        return formatter.format(instant);
    }
}
