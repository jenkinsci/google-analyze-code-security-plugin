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

package io.jenkins.plugins.google.analyze.code.security.exception;

import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.NonNull;
import lombok.ToString;

/**
 * IACValidationException represents exception occurred while invoking IAC validation service.
 */
@EqualsAndHashCode(callSuper = true)
@Data
@ToString(callSuper = true)
public class IACValidationException extends RuntimeException {

    private final Integer statusCode;

    public IACValidationException(@NonNull final Integer statusCode, @NonNull final String message) {
        super(message);
        this.statusCode = statusCode;
    }

    public IACValidationException(@NonNull final Integer statusCode, @NonNull final String message,
                                  @NonNull final Throwable cause) {
        super(message, cause);
        this.statusCode = statusCode;
    }
}
