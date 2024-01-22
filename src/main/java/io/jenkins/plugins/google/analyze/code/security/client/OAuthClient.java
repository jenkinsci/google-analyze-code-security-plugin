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

package io.jenkins.plugins.google.analyze.code.security.client;

import com.google.auth.oauth2.AccessToken;
import com.google.auth.oauth2.GoogleCredentials;
import lombok.NonNull;
import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.util.Collection;

import static io.jenkins.plugins.google.analyze.code.security.commons.CustomerMessage.MALFORMED_SCC_CREDENTIAL;

/**
 * OAuthClient provides Client for managing OAuth token lifecycle.
 */
public class OAuthClient {

    private static OAuthClient instance;

    /**
     * Returns an instance of {@link OAuthClient}
     */
    public static OAuthClient getInstance() {
        if (instance == null) {
            instance = new OAuthClient();
        }
        return instance;
    }

    private OAuthClient() {
    }

    /**
     * Generates OAuth access token with the help of GCP Service Account Credentials.
     *
     * @param credential GCP Service Account Credentials.
     * @param scopes Collection of scopes to request.
     */
    public String generateAccessToken(@NonNull final String credential, @NonNull final Collection<String> scopes) {
        try {
            final GoogleCredentials credentials = GoogleCredentials.fromStream(
                            new ByteArrayInputStream(credential.getBytes(StandardCharsets.UTF_8)))
                    .createScoped(scopes);
            credentials.refreshIfExpired();
            final AccessToken token = credentials.getAccessToken();
            return token.getTokenValue();
        } catch (Exception ex) {
            throw new IllegalArgumentException(MALFORMED_SCC_CREDENTIAL);
        }
    }
}
