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

import io.jenkins.plugins.google.analyze.code.security.accessor.ExponentialBackoffRetryHandler;
import io.jenkins.plugins.google.analyze.code.security.commons.Config;
import org.apache.http.HttpHeaders;
import org.apache.http.HttpResponse;
import org.apache.http.HttpStatus;
import org.apache.http.StatusLine;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.ContentType;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.protocol.HttpContext;
import java.io.IOException;
import java.util.List;

/**
 * HttpClient provides Client Object for Http Based communication.
 */
public class HttpClient {
    public final static List<Integer> RETRIABLE_ERROR_CODES = List.of(HttpStatus.SC_REQUEST_TIMEOUT,
            HttpStatus.SC_TOO_MANY_REQUESTS, HttpStatus.SC_INTERNAL_SERVER_ERROR, HttpStatus.SC_BAD_GATEWAY,
            HttpStatus.SC_SERVICE_UNAVAILABLE, HttpStatus.SC_GATEWAY_TIMEOUT);
    private static HttpClient instance;

    /**
     * Returns an instance of {@link HttpClient}
     */
    public static HttpClient getInstance() {
        if (instance == null) {
            instance = new HttpClient();
        }
        return instance;
    }

    private HttpClient() {
    }

    /**
     * Returns HttpClientBuilder instance.
     *
     * @param maxRetryCount maximum count of retries
     */
    public HttpClientBuilder getHttpClientBuilder(final Integer maxRetryCount) {
        return HttpClientBuilder.create()
                .addInterceptorLast((HttpResponse response, HttpContext context) -> {
                    StatusLine statusLine = response.getStatusLine();
                    if (RETRIABLE_ERROR_CODES.contains(statusLine.getStatusCode())) {
                        throw new IOException(String.format("Received Exception with status code : [%s] & reason : [%s]",
                                statusLine.getStatusCode(), statusLine.getReasonPhrase()));
                    }
                })
                .setRetryHandler(ExponentialBackoffRetryHandler.getDefault(maxRetryCount));
    }

    /**
     * Build POST Request Client.
     *
     * @param url http url that should be accessed.
     * @param jsonReq request payload.
     * @param accessToken OAuth access token.
     */
    public HttpPost buildPOSTRequest(final String url, final String jsonReq, final String accessToken) {
        final HttpPost httppost = new HttpPost(url);
        httppost.setEntity(new StringEntity(jsonReq, ContentType.APPLICATION_JSON));
        httppost.setConfig(RequestConfig.custom()
                .setConnectTimeout(Config.CONNECTION_TIMEOUT_BYTES)
                .setConnectionRequestTimeout(Config.CONNECTION_REQUEST_TIMEOUT_BYTES)
                .build());
        httppost.setHeader(HttpHeaders.CONTENT_TYPE, "application/json");
        httppost.setHeader(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken);
        return httppost;
    }

    /**
     * Builds GET Request Client.
     *
     * @param url http url that should be accessed.
     * @param accessToken OAuth access token.
     */
    public HttpGet buildGETRequest(final String url, final String accessToken) {
        final HttpGet httpGet = new HttpGet(url);
        httpGet.setConfig(RequestConfig.custom()
                .setConnectTimeout(Config.CONNECTION_TIMEOUT_BYTES)
                .setConnectionRequestTimeout(Config.CONNECTION_REQUEST_TIMEOUT_BYTES)
                .build());
        httpGet.setHeader(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken);
        return httpGet;
    }
}
