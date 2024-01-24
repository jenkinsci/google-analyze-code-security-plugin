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

import static io.jenkins.plugins.google.analyze.code.security.commons.CustomerMessage.INVALID_REQUEST;
import static io.jenkins.plugins.google.analyze.code.security.commons.CustomerMessage.INVALID_SCAN_FILE_SIZE;
import static io.jenkins.plugins.google.analyze.code.security.commons.CustomerMessage.MALFORMED_SCAN_FILE;
import static org.apache.commons.lang.StringUtils.isBlank;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.annotations.VisibleForTesting;
import hudson.model.BuildListener;
import hudson.util.Secret;
import io.jenkins.plugins.google.analyze.code.security.client.HttpClient;
import io.jenkins.plugins.google.analyze.code.security.client.OAuthClient;
import io.jenkins.plugins.google.analyze.code.security.commons.Config;
import io.jenkins.plugins.google.analyze.code.security.commons.CustomerMessage;
import io.jenkins.plugins.google.analyze.code.security.commons.ReportConstants;
import io.jenkins.plugins.google.analyze.code.security.exception.IACValidationException;
import io.jenkins.plugins.google.analyze.code.security.model.IACValidationService.ValidateIACParams;
import io.jenkins.plugins.google.analyze.code.security.model.IACValidationService.request.IAC;
import io.jenkins.plugins.google.analyze.code.security.model.IACValidationService.request.Request;
import io.jenkins.plugins.google.analyze.code.security.model.IACValidationService.response.IaCValidationReport;
import io.jenkins.plugins.google.analyze.code.security.model.IACValidationService.response.Response;
import io.jenkins.plugins.google.analyze.code.security.model.IACValidationService.response.Severity;
import io.jenkins.plugins.google.analyze.code.security.model.IACValidationService.response.Violation;
import io.jenkins.plugins.google.analyze.code.security.utils.LogUtils;
import io.jenkins.plugins.google.analyze.code.security.utils.ValidationUtils;
import java.io.IOException;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import lombok.NonNull;
import org.apache.commons.lang.StringUtils;
import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.HttpStatus;
import org.apache.http.StatusLine;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.util.EntityUtils;
import org.springframework.security.access.AccessDeniedException;

/**
 * IACValidationService provides functionality for interfacing with SCC IAC Validation API,
 * validating and processing response.
 */
public class IACValidationService {
    private static final String VALIDATE_ENDPOINT_DOMAIN =
            "https://staging-securityposture-googleapis.sandbox.google.com/v1alpha";
    private static final String VALIDATE_ENDPOINT_PATH =
            "/organizations/{ORG_ID}/locations/global/reports:createIaCValidationReport";
    private static final String VALIDATE_URL = VALIDATE_ENDPOINT_DOMAIN + VALIDATE_ENDPOINT_PATH;
    private static final String ORG_ID_PLACEHOLDER = "{ORG_ID}";
    private static final String GCP_AUTH_SCOPE = "https://www.googleapis.com/auth/cloud-platform";
    private static final ObjectMapper mapper = getObjectMapper();

    private static IACValidationService instance;

    private final HttpClient httpClient;
    private final OAuthClient oAuthClient;

    /**
     * Returns an instance of {@link IACValidationService}
     */
    public static IACValidationService getInstance() {
        if (instance == null) {
            instance = new IACValidationService(HttpClient.getInstance(), OAuthClient.getInstance());
        }
        return instance;
    }

    @VisibleForTesting
    public IACValidationService(final HttpClient httpClient, final OAuthClient oAuthClient) {
        this.httpClient = httpClient;
        this.oAuthClient = oAuthClient;
    }

    /**
     * Invokes SCC IAC Validation Service, processes response and polls on the operation URL
     * to get the validation report.
     *
     * @return violations detected in the IAC file.
     */
    public List<Violation> validateIAC(@NonNull final ValidateIACParams validateIACParams) {
        final PrintStream printStream = validateIACParams.getListener().getLogger();
        printStream.print(LogUtils.info("Invoking IAC Validating Service for validating  Scan file"));
        validateIACValidationRequest(
                validateIACParams.getFile(),
                validateIACParams.getOrgID(),
                validateIACParams.getCredentials().getPlainText());
        final String url = StringUtils.replace(VALIDATE_URL, ORG_ID_PLACEHOLDER, validateIACParams.getOrgID());
        try (CloseableHttpClient closeableHttpClient =
                httpClient.getHttpClientBuilder(/* maxRetryCount= */ 3).build()) {
            final String jsonReq =
                    mapper.writeValueAsString(buildRequest(validateIACParams.getFile(), validateIACParams.getOrgID()));
            HttpPost httppost = httpClient.buildPOSTRequest(
                    url,
                    jsonReq,
                    oAuthClient.generateAccessToken(
                            validateIACParams.getCredentials().getPlainText(), Collections.singleton(GCP_AUTH_SCOPE)));
            printStream.printf(LogUtils.info("Requesting Validation Service Polling Endpoint from : %s"), url);
            String resJSON = closeableHttpClient.execute(httppost, this::handleIACValidationResponse);
            Response response = mapper.readValue(resJSON, Response.class);
            if (response == null || isBlank(response.getName())) {
                throw new IACValidationException(
                        /* statusCode= */ 500,
                        "[Internal Error] Received Invalid Response "
                                + "while requesting Validation Service Polling Endpoint");
            }
            printStream.print(LogUtils.info("Received Validation Service Polling Endpoint"));
            return pollValidateEndpoint(
                    VALIDATE_ENDPOINT_DOMAIN + "/" + response.getName(),
                    validateIACParams.getRequestReceiveInstant(),
                    validateIACParams.getPluginTimeoutInMS(),
                    validateIACParams.getListener(),
                    validateIACParams.getCredentials().getPlainText());
        } catch (Exception ex) {
            Integer statusCode = 500;
            if (ex instanceof IACValidationException) {
                statusCode = ((IACValidationException) ex).getStatusCode();
            }
            if (ex instanceof IllegalArgumentException) {
                statusCode = 400;
            }
            throw new IACValidationException(
                    statusCode, String.format(CustomerMessage.IAC_VALIDATION_EXCEPTION_MSG, ex.getMessage()), ex);
        }
    }

    /**
     * Validate SCC Credentials Corresponding to the OrgId.
     *
     * @param orgID GCP organizationId
     * @param credential SCC credential corresponding to the orgID.
     * @throws IOException scenarios where exception occurs during network I/O or request serialization.
     */
    public void validateCredentials(final String orgID, final Secret credential) throws IOException {
        final byte[] file = ReportConstants.DUMMY_INVALID_IAC_FILE.getBytes(StandardCharsets.UTF_8);
        validateIACValidationRequest(file, orgID, credential.getPlainText());
        final Request request = buildRequest(file, orgID);
        final String url = StringUtils.replace(VALIDATE_URL, ORG_ID_PLACEHOLDER, request.getParent());
        try (CloseableHttpClient closeableHttpClient =
                httpClient.getHttpClientBuilder(/*maxRetryCount=*/ 1).build()) {
            final String jsonReq = mapper.writeValueAsString(request);
            HttpPost httppost = httpClient.buildPOSTRequest(
                    url,
                    jsonReq,
                    oAuthClient.generateAccessToken(credential.getPlainText(), Collections.singleton(GCP_AUTH_SCOPE)));
            closeableHttpClient.execute(httppost, (this::handleCredentialValidationResponse));
        }
    }

    private List<Violation> pollValidateEndpoint(
            final String url,
            @NonNull final Instant requestReceiveInstant,
            @NonNull final Integer pluginTimeoutInMS,
            @NonNull final BuildListener listener,
            @NonNull final String credentials) {
        Response response = null;
        int pollCount = 0;
        final ExponentialBackoffRetryHandler backoffRetryHandler =
                ExponentialBackoffRetryHandler.getDefault(Config.VALIDATE_ENDPOINT_POLL_MAX_ATTEMPT);
        final Instant pluginTimeOutInstant = requestReceiveInstant.plusMillis(pluginTimeoutInMS);
        while (pluginTimeOutInstant.compareTo(Instant.now().plusMillis(Config.POLL_ATTEMPT_BUFFER_TIME_MILLIS)) > 0) {
            try (CloseableHttpClient closeableHttpClient =
                    httpClient.getHttpClientBuilder(/*maxRetryCount=*/ 1).build()) {
                HttpGet httpGet = httpClient.buildGETRequest(
                        url, oAuthClient.generateAccessToken(credentials, Collections.singleton(GCP_AUTH_SCOPE)));
                listener.getLogger()
                        .printf(LogUtils.info("Polling Validation Service Endpoint, Attempt Count : [%s]"), pollCount);
                String resJSON = closeableHttpClient.execute(httpGet, this::handleIACValidationResponse);
                response = mapper.readValue(resJSON, Response.class);
                listener.getLogger().print(LogUtils.info("Received Response from Validation Service Endpoint"));
                if (response != null && response.getDone().equals(Boolean.TRUE)) {
                    break;
                }
            } catch (Exception ex) {
                listener.getLogger()
                        .printf(
                                LogUtils.error("Received Error while polling Validation Service Endpoint : " + "[%s]"),
                                ex);
            } finally {
                pollCount += 1;
                if (!backoffRetryHandler.retryRequestWithDelay(pollCount)) {
                    break;
                }
            }
        }

        validatePollResponse(response);
        return processResponse(response.getResult().getValidationReport().getViolations());
    }

    private void validatePollResponse(final Response response) {
        if (response == null || response.getDone().equals(false)) {
            throw new IACValidationException(500, "[Internal Error]  Polling Validation Service Endpoint Timed Out");
        }
        if (response.getError() != null) {
            throw new IACValidationException(
                    response.getError().getCode(),
                    String.format(
                            "Validation Service Endpoint" + "Returned Error Response with following error : [%s]",
                            response.getError().getMessage()));
        }
        final List<Violation> violations = getViolations(response);
        if (violations == null) {
            return;
        }
        for (Violation violation : violations) {
            if (violation.getPolicyId() == null || violation.getAssetId() == null) {
                throw new IACValidationException(
                        500,
                        String.format(
                                "[Internal Error] Validation Service Endpoint Returned "
                                        + "Invalid violations with one or more missing key Attributes, policyID : [%s], assetId : [%s]",
                                violation.getPolicyId(), violation.getAssetId()));
            }
        }
    }

    private List<Violation> getViolations(final Response response) {
        if (response.getResult() == null) {
            throw new IACValidationException(
                    500, "[Internal Error] Validation Polling Endpoint Returned Null Response");
        }
        final IaCValidationReport validationReport = response.getResult().getValidationReport();
        if (validationReport == null) {
            throw new IACValidationException(
                    500, "[Internal Error] Validation Endpoint Returned Response with " + "Invalid validationReport");
        }
        return validationReport.getViolations();
    }

    private void validateIACValidationRequest(final byte[] file, final String orgID, final String credential) {
        validateScanFile(file);
        if (!ValidationUtils.isValidOrgId(orgID)) {
            throw new IllegalArgumentException(
                    String.format(CustomerMessage.INVALID_REQUEST, CustomerMessage.INVALID_ORG_ID));
        }
        if (!ValidationUtils.isValidJSON(credential)) {
            throw new IllegalArgumentException(String.format(
                    CustomerMessage.INVALID_REQUEST, String.format(CustomerMessage.INVALID_SCC_CREDENTIAL, orgID)));
        }
    }

    private Request buildRequest(final byte[] file, final String orgID) {
        final IAC iac = IAC.builder().file(file).build();
        return Request.builder().parent(orgID).iac(iac).build();
    }

    /**
     * Adds default handling in the SCC Response which is missing as PROTO3 to JSON
     * conversion is not taking into account defaults.
     */
    private List<Violation> processResponse(final List<Violation> violations) {
        if (violations == null) return new ArrayList<>();
        for (Violation violation : violations) {
            if (violation.getSeverity() == null) {
                violation.setSeverity(Severity.SEVERITY_UNSPECIFIED);
            }
        }
        return violations;
    }

    private void validateScanFile(final byte[] tfPlanJSON) {
        if (tfPlanJSON.length > Config.SCAN_FILE_MAX_SIZE_BYTES) {
            throw new IllegalArgumentException(String.format(
                    INVALID_REQUEST,
                    String.format(INVALID_SCAN_FILE_SIZE, tfPlanJSON.length, Config.SCAN_FILE_MAX_SIZE_BYTES)));
        }
        if (!ValidationUtils.isValidJSONFile(tfPlanJSON)) {
            throw new IllegalArgumentException(String.format(INVALID_REQUEST, MALFORMED_SCAN_FILE));
        }
    }

    private static ObjectMapper getObjectMapper() {
        final ObjectMapper mapper = new ObjectMapper();
        mapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
        mapper.enable(DeserializationFeature.ACCEPT_SINGLE_VALUE_AS_ARRAY);
        return mapper;
    }

    /**
     * Handles response and checks against `403` status code. Throws {@link AccessDeniedException} in
     * scenarios when response's status code is set as `403`.
     *
     * <p>
     *     Only handles failure scenarios where server denied request processing due to authentication or authorization
     *     failures. For all other success/failure scenarios where server accepted request we consider credentials
     *     were valid.
     * </p>
     * @param response HTTP response message.
     * @return response fixed message, as response is not the desired output and only returned to comply with the
     * {@code ResponseHandler} functional interface signature.
     */
    private String handleCredentialValidationResponse(final HttpResponse response) {
        StatusLine statusLine = response.getStatusLine();
        if (statusLine.getStatusCode() == HttpStatus.SC_FORBIDDEN) {
            throw new AccessDeniedException(String.format(
                    "Received Access Denied Exception with status Code : %s & Reason : %s",
                    statusLine.getStatusCode(), statusLine.getReasonPhrase()));
        }
        return "SuccessFully Validated Credentials";
    }

    /**
     * Handles response and throws {@link IACValidationException} in
     * scenarios when response's status code is other than `200`.
     *
     * @param response HTTP response message.
     * @return response body
     * @throws IOException scenarios where exception occurs during network I/O or request serialization.
     */
    private String handleIACValidationResponse(final HttpResponse response) throws IOException {
        StatusLine statusLine = response.getStatusLine();
        if (statusLine.getStatusCode() != HttpStatus.SC_OK) {
            throw new IACValidationException(statusLine.getStatusCode(), statusLine.getReasonPhrase());
        }
        HttpEntity entity = response.getEntity();
        if (entity == null) {
            throw new ClientProtocolException("Response contains no content");
        }
        return EntityUtils.toString(entity);
    }
}
