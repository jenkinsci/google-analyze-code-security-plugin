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

package io.jenkins.plugins.google.analyze.code.security.accessor;

import com.google.api.client.util.ExponentialBackOff;
import org.apache.http.client.HttpRequestRetryHandler;
import org.apache.http.protocol.HttpContext;
import java.io.IOException;

/**
 * ExponentialBackoffRetryHandler provides implementation for Backoff Retry Strategy.
 */
public class ExponentialBackoffRetryHandler implements HttpRequestRetryHandler {
    private final int maxNumRetries;
    private final double backOffRate;
    private final int initialExpiry;
    private final int maxBackOff;

    private ExponentialBackoffRetryHandler(int maxNumRetries, double backOffRate, int initialExpiry, int maxBackOff) {
        this.maxNumRetries = maxNumRetries;
        this.backOffRate = backOffRate;
        this.initialExpiry = initialExpiry;
        this.maxBackOff = maxBackOff;
    }

    @Override
    public boolean retryRequest(IOException exception, int executionCount, HttpContext context) {
        return retryRequestWithDelay(executionCount);
    }

    /**
     * Evaluates whether the request should be retried based on executionCount and adds a delay
     * for scenarios where request should be retried.
     *
     * @param executionCount current attempt count
     */
    public boolean retryRequestWithDelay(int executionCount) {
        if (executionCount <= 0) {
            throw new IllegalArgumentException("ExecutionCont should always be greater than zero");
        }
        if (executionCount == maxNumRetries) {
            return false;
        }
        long nextBackOffDelay = (long) (initialExpiry * Math.pow(backOffRate, executionCount - 1));
        long delay = Math.min(maxBackOff, nextBackOffDelay);
        addDelay(delay);
        return true;
    }

    /**
     * Provides implementation of {@link ExponentialBackoffRetryHandler} with configurable maxRetryCount.
     *
     * @param maxRetryCount max number of retries.
     * @return instance of {@link ExponentialBackoffRetryHandler}
     */
    public static ExponentialBackoffRetryHandler getDefault(final int maxRetryCount) {
        return new ExponentialBackoffRetryHandler(maxRetryCount, ExponentialBackOff.DEFAULT_MULTIPLIER,
                ExponentialBackOff.DEFAULT_INITIAL_INTERVAL_MILLIS, ExponentialBackOff.DEFAULT_MAX_INTERVAL_MILLIS);
    }

    private void addDelay(final long delay) {
        try {
            Thread.sleep(delay);
        } catch (InterruptedException ignored) {
        }
    }
}
