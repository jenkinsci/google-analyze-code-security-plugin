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

import static io.jenkins.plugins.google.analyze.code.security.commons.TestUtil.*;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyCollection;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.atMost;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import hudson.model.BuildListener;
import hudson.util.Secret;
import io.jenkins.plugins.google.analyze.code.security.client.HttpClient;
import io.jenkins.plugins.google.analyze.code.security.client.OAuthClient;
import io.jenkins.plugins.google.analyze.code.security.commons.Config;
import io.jenkins.plugins.google.analyze.code.security.exception.IACValidationException;
import io.jenkins.plugins.google.analyze.code.security.model.IACValidationService.ValidateIACParams;
import io.jenkins.plugins.google.analyze.code.security.model.IACValidationService.response.IaCValidationReport;
import io.jenkins.plugins.google.analyze.code.security.model.IACValidationService.response.OperationMetadata;
import io.jenkins.plugins.google.analyze.code.security.model.IACValidationService.response.Response;
import io.jenkins.plugins.google.analyze.code.security.model.IACValidationService.response.Result;
import io.jenkins.plugins.google.analyze.code.security.model.IACValidationService.response.Violation;
import java.io.IOException;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.AccessDeniedException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import org.apache.http.HttpStatus;
import org.apache.http.client.ResponseHandler;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.hamcrest.core.IsEqual;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

/**
 * IACValidationServiceTest test for {@link IACValidationService}.
 */
@RunWith(MockitoJUnitRunner.class)
public class IACValidationServiceTest {
    private static final String DUMMY_CREDENTIALS = "{\"testKey\" : \"testVal\"}";
    private static final String DUMMY_ACCESS_TOKEN = "access_token";
    private static final String DUMMY_SCAN_FILE = "{\"assetId\" : \"assetVal\"}";
    private static final String DUMMY_JSON_POLL_ENDPOINT_RES = "{\n"
            + "  \"name\": \"organizations/627849321070/locations/global/operations/operation-1704446435860-60e2f5c592090-44537b85-4e5c383b\",\n"
            + "  \"metadata\": {\n"
            + "    \"@type\": \"type.googleapis.com/google.cloud.securityposture.v1.OperationMetadata\",\n"
            + "    \"createTime\": \"2024-01-05T09:20:35.889386783Z\",\n"
            + "    \"target\": \"organizations/627849321070/locations/global/reports/f501fae7-6e6b-4058-8782-c80670022f3e\",\n"
            + "    \"verb\": \"create\",\n"
            + "    \"requestedCancellation\": false,\n"
            + "    \"apiVersion\": \"v1\"\n"
            + "  },\n"
            + "  \"done\": false\n"
            + "}";
    private static final String DUMMY_JSON_EMPTY_POLL_ENDPOINT_RES = "{\n" + "  \"name\": \"\",\n"
            + "  \"metadata\": {\n"
            + "    \"@type\": \"type.googleapis.com/google.cloud.securityposture.v1.OperationMetadata\",\n"
            + "    \"createTime\": \"2024-01-05T09:20:35.889386783Z\",\n"
            + "    \"target\": \"organizations/627849321070/locations/global/reports/f501fae7-6e6b-4058-8782-c80670022f3e\",\n"
            + "    \"verb\": \"create\",\n"
            + "    \"requestedCancellation\": false,\n"
            + "    \"apiVersion\": \"v1\"\n"
            + "  },\n"
            + "  \"done\": false\n"
            + "}";
    private static final String DUMMY_JSON_EMPTY_VIOLATIONS_RES = "{\n"
            + "    \"name\": \"organizations/627849321070/locations/global/operations/operation-1704444122295-60e2ed272ed68-625d72a8-6fd29abb\",\n"
            + "    \"metadata\": {\n"
            + "        \"@type\": \"type.googleapis.com/google.cloud.securityposture.v1.OperationMetadata\",\n"
            + "        \"createTime\": \"2024-01-05T08:42:02.325485680Z\",\n"
            + "        \"endTime\": \"2024-01-05T08:42:02.473852683Z\",\n"
            + "        \"target\": \"organizations/627849321070/locations/global/reports/142336eb-5c66-4283-bb3e-681595ac0644\",\n"
            + "        \"verb\": \"create\",\n"
            + "        \"requestedCancellation\": false,\n"
            + "        \"apiVersion\": \"v1\"\n"
            + "    },\n"
            + "    \"done\": true,\n"
            + "    \"response\": {\n"
            + "        \"@type\": \"type.googleapis.com/google.cloud.securityposture.v1.Report\",\n"
            + "        \"name\": \"organizations/627849321070/locations/global/reports/142336eb-5c66-4283-bb3e-681595ac0644\",\n"
            + "        \"createTime\": \"2024-01-05T08:42:02.302457702Z\",\n"
            + "        \"updateTime\": \"2024-01-05T08:42:02.302457702Z\",\n"
            + "        \"iacValidationReport\": {\n"
            + "             \"note\": \"IaC validation is limited to certain asset types and policies. For information about supported asset types and policies for IaC validation, see https://cloud.google.com/security-command-center/docs/supported-iac-assets-policies.\"\n"
            + "        }\n"
            + "    }\n"
            + "}";
    private static final String DUMMY_JSON_NON_EMPTY_VIOLATIONS_RES = "{\n"
            + "  \"name\": \"organizations/627849321070/locations/global/operations/operation-1703707216002-60d833f693fab-94a01344-ae728e4f\",\n"
            + "  \"metadata\": {\n"
            + "    \"@type\": \"type.googleapis.com/google.cloud.securityposture.v1.OperationMetadata\",\n"
            + "    \"createTime\": \"2024-12-27T20:00:16.070421839Z\",\n"
            + "    \"endTime\": \"2024-12-27T20:00:16.126303630Z\",\n"
            + "    \"target\": \"organizations/627849321070/locations/global/reports/182db54a-95de-4c10-b9f9-624a92ab8e3c\",\n"
            + "    \"verb\": \"create\",\n"
            + "    \"requestedCancellation\": false,\n"
            + "    \"apiVersion\": \"v1\"\n"
            + "  },\n"
            + "  \"done\": true,\n"
            + "  \"response\": {\n"
            + "    \"@type\": \"type.googleapis.com/google.cloud.securityposture.v1.Report\",\n"
            + "    \"name\": \"organizations/627849321070/locations/global/reports/182db54a-95de-4c10-b9f9-624a92ab8e3c\",\n"
            + "    \"createTime\": \"2024-12-27T20:00:16.012019593Z\",\n"
            + "    \"updateTime\": \"2024-12-27T20:00:16.012019593Z\",\n"
            + "    \"iacValidationReport\": {\n"
            + "      \"violations\": [\n"
            + "        {\n"
            + "          \"assetId\": \"storage.googleapis.com/buckets/b1\",\n"
            + "          \"policyId\": \"folders/123456/policies/custom.publicBucketACL\",\n"
            + "          \"violatedPosture\": {\n"
            + "            \"postureDeployment\": \"organizations/627849321070/locations/global/postureDeployments/pd1\",\n"
            + "            \"postureDeploymentTargetResource\": \"folders/123456\",\n"
            + "            \"posture\": \"organizations/627849321070/locations/global/postures/posture1\",\n"
            + "            \"postureRevisionId\": \"rev1\",\n"
            + "            \"policySet\": \"my-policy-set-1\"\n"
            + "          },\n"
            + "          \"severity\": \"CRITICAL\",\n"
            + "          \"nextSteps\": \"You can fix this by following Step 1, Step 2 and Step 3\",\n"
            + "          \"violatedAsset\": {\n"
            + "            \"asset\": \"some json representation of asset\",\n"
            + "            \"assetType\": \"storage.googleapis.com/Bucket\"\n"
            + "          },\n"
            + "          \"violatedPolicy\": {\n"
            + "            \"constraint\": \"some json representation of constraint\",\n"
            + "            \"constraintType\": \"ORG_POLICY_CUSTOM\",\n"
            + "            \"complianceStandards\": [\n"
            + "              \"CIS 2.0 1.15\",\n"
            + "              \"NIST 1.5\"\n"
            + "            ],\n"
            + "            \"description\": \"detailed description\"\n"
            + "          }\n"
            + "        },\n"
            + "        {\n"
            + "          \"assetId\": \"storage.googleapis.com/buckets/b2\",\n"
            + "          \"policyId\": \"folders/123456/policies/custom.uniformBucketLevelAccess\",\n"
            + "          \"severity\": \"LOW\",\n"
            + "          \"violatedPolicy\": {\n"
            + "            \"constraint\": \"some json representation of constraint\",\n"
            + "            \"constraintType\": \"ORG_POLICY_CUSTOM\",\n"
            + "            \"complianceStandards\": [\n"
            + "              \"NIST 3\"\n"
            + "            ],\n"
            + "            \"description\": \"detailed description\"\n"
            + "          }\n"
            + "        },\n"
            + "        {\n"
            + "          \"assetId\": \"storage.googleapis.com/buckets/b3\",\n"
            + "          \"policyId\": \"folders/123456/policies/custom.uniformBucketLevelAccess\",\n"
            + "          \"severity\": \"LOW\"\n"
            + "        }\n"
            + "      ],\n"
            + "             \"note\": \"IaC validation is limited to certain asset types and policies. For information about supported asset types and policies for IaC validation, see https://cloud.google.com/security-command-center/docs/supported-iac-assets-policies.\"\n"
            + "    }\n"
            + "  }\n"
            + "}";

    private IACValidationService iacValidationService;

    @Mock
    private HttpClient httpClient;

    @Mock
    private OAuthClient oAuthClient;

    @Mock
    private BuildListener listener;

    @Mock
    private PrintStream printStream;

    @Mock
    private HttpClientBuilder httpClientBuilder;

    @Mock
    private CloseableHttpClient closeableHttpClient;

    @Mock
    private HttpPost httpPost;

    @Mock
    private HttpGet httpGet;

    @Before
    public void setup() {
        when(listener.getLogger()).thenReturn(printStream);
        when(httpClient.getHttpClientBuilder(anyInt())).thenReturn(httpClientBuilder);
        when(httpClientBuilder.build()).thenReturn(closeableHttpClient);
        when(oAuthClient.generateAccessToken(anyString(), anyCollection())).thenReturn(DUMMY_ACCESS_TOKEN);
        when(httpClient.buildPOSTRequest(anyString(), anyString(), anyString())).thenReturn(httpPost);
        when(httpClient.buildGETRequest(anyString(), anyString())).thenReturn(httpGet);
        iacValidationService = new IACValidationService(httpClient, oAuthClient);
    }

    @Test
    public void validateIAC_validParams_returnsNonEmptyViolations() throws IOException {
        final Response response = buildResponse(DUMMY_VIOLATIONS);
        when(closeableHttpClient.execute(eq(httpPost), any(ResponseHandler.class)))
                .thenReturn(DUMMY_JSON_POLL_ENDPOINT_RES);
        when(closeableHttpClient.execute(eq(httpGet), any(ResponseHandler.class)))
                .thenReturn(DUMMY_JSON_NON_EMPTY_VIOLATIONS_RES);

        final IaCValidationReport report = iacValidationService.validateIAC(getValidIACValidationRequest(listener));

        assertEquals(report, response.getResult().getValidationReport());
        verify(closeableHttpClient, times(/*wantedNumberOfInvocations=*/ 1))
                .execute(eq(httpPost), any(ResponseHandler.class));
        verify(oAuthClient, times(/*wantedNumberOfInvocations=*/ 2))
                .generateAccessToken(eq(DUMMY_CREDENTIALS), anyCollection());
        verify(closeableHttpClient, times(/*wantedNumberOfInvocations=*/ 1))
                .execute(eq(httpGet), any(ResponseHandler.class));
    }

    @Test
    public void validateIAC_validParams_returnsEmptyViolations() throws IOException {
        final Response response = buildResponse(new ArrayList<>());
        when(closeableHttpClient.execute(eq(httpPost), any(ResponseHandler.class)))
                .thenReturn(DUMMY_JSON_POLL_ENDPOINT_RES);
        when(closeableHttpClient.execute(eq(httpGet), any(ResponseHandler.class)))
                .thenReturn(DUMMY_JSON_EMPTY_VIOLATIONS_RES);

        final IaCValidationReport report = iacValidationService.validateIAC(getValidIACValidationRequest(listener));

        assertEquals(report, response.getResult().getValidationReport());
        verify(closeableHttpClient, times(/*wantedNumberOfInvocations=*/ 1))
                .execute(eq(httpPost), any(ResponseHandler.class));
        verify(oAuthClient, times(/*wantedNumberOfInvocations=*/ 2))
                .generateAccessToken(eq(DUMMY_CREDENTIALS), anyCollection());
        verify(closeableHttpClient, times(/*wantedNumberOfInvocations=*/ 1))
                .execute(eq(httpGet), any(ResponseHandler.class));
    }

    @Test
    public void validateIAC_SCCReturnsInvalidPollingEndpoint_throwsIACValidationException() throws IOException {
        when(closeableHttpClient.execute(eq(httpPost), any(ResponseHandler.class)))
                .thenReturn(DUMMY_JSON_EMPTY_POLL_ENDPOINT_RES);

        IACValidationException thrown = assertThrows(
                IACValidationException.class,
                () -> iacValidationService.validateIAC(getValidIACValidationRequest(listener)));

        assertThat(thrown.getStatusCode(), IsEqual.equalTo(HttpStatus.SC_INTERNAL_SERVER_ERROR));
        verify(closeableHttpClient, times(/*wantedNumberOfInvocations=*/ 1))
                .execute(eq(httpPost), any(ResponseHandler.class));
        verify(oAuthClient, times(/*wantedNumberOfInvocations=*/ 1))
                .generateAccessToken(eq(DUMMY_CREDENTIALS), anyCollection());
        verify(closeableHttpClient, times(/*wantedNumberOfInvocations=*/ 0))
                .execute(eq(httpGet), any(ResponseHandler.class));
    }

    @Test
    public void validateIAC_validParams_returnsViolationsAfterTwoPollingAttempts() throws IOException {
        final Response response = buildResponse(DUMMY_VIOLATIONS);
        when(closeableHttpClient.execute(eq(httpPost), any(ResponseHandler.class)))
                .thenReturn(DUMMY_JSON_POLL_ENDPOINT_RES);
        when(closeableHttpClient.execute(eq(httpGet), any(ResponseHandler.class)))
                .thenReturn(DUMMY_JSON_POLL_ENDPOINT_RES)
                .thenReturn(DUMMY_JSON_NON_EMPTY_VIOLATIONS_RES);

        final IaCValidationReport report = iacValidationService.validateIAC(getValidIACValidationRequest(listener));

        assertEquals(report, response.getResult().getValidationReport());
        verify(closeableHttpClient, times(/*wantedNumberOfInvocations=*/ 1))
                .execute(eq(httpPost), any(ResponseHandler.class));
        verify(oAuthClient, times(/*wantedNumberOfInvocations=*/ 3))
                .generateAccessToken(eq(DUMMY_CREDENTIALS), anyCollection());
        verify(closeableHttpClient, times(/*wantedNumberOfInvocations=*/ 2))
                .execute(eq(httpGet), any(ResponseHandler.class));
    }

    @Test
    public void validateIAC_SCCAPITimesOut_throwsIACValidationException() throws IOException {
        when(closeableHttpClient.execute(eq(httpPost), any(ResponseHandler.class)))
                .thenReturn(DUMMY_JSON_POLL_ENDPOINT_RES);
        when(closeableHttpClient.execute(eq(httpGet), any(ResponseHandler.class)))
                .thenReturn(DUMMY_JSON_POLL_ENDPOINT_RES);

        IACValidationException thrown = assertThrows(
                IACValidationException.class,
                () -> iacValidationService.validateIAC(getValidIACValidationRequest(listener)));

        assertThat(thrown.getStatusCode(), IsEqual.equalTo(/*operand=*/ 500));
        verify(closeableHttpClient, times(/*wantedNumberOfInvocations=*/ 1))
                .execute(eq(httpPost), any(ResponseHandler.class));
        verify(closeableHttpClient, atMost(Config.POLL_ATTEMPT_BUFFER_TIME_MILLIS))
                .execute(eq(httpGet), any(ResponseHandler.class));
    }

    @Test
    public void validateCredentials_validCredential_noExceptionThrown() throws IOException {
        iacValidationService.validateCredentials(DUMMY_ORG_ID, Secret.fromString(DUMMY_CREDENTIALS));

        verify(closeableHttpClient, times(/*wantedNumberOfInvocations=*/ 1))
                .execute(eq(httpPost), any(ResponseHandler.class));
    }

    @Test
    public void validateCredentials_invalidCredential_throwsAccessDeniedException() throws IOException {
        when(closeableHttpClient.execute(eq(httpPost), any(ResponseHandler.class)))
                .thenThrow(AccessDeniedException.class);

        assertThrows(
                AccessDeniedException.class,
                () -> iacValidationService.validateCredentials(DUMMY_ORG_ID, Secret.fromString(DUMMY_CREDENTIALS)));

        verify(closeableHttpClient, times(/*wantedNumberOfInvocations=*/ 1))
                .execute(eq(httpPost), any(ResponseHandler.class));
    }

    private ValidateIACParams getValidIACValidationRequest(final BuildListener listener) {
        return ValidateIACParams.builder()
                .file(DUMMY_SCAN_FILE.getBytes(StandardCharsets.UTF_8))
                .orgID(DUMMY_ORG_ID)
                .credentials(Secret.fromString(DUMMY_CREDENTIALS))
                .pluginTimeoutInMS(Config.SCAN_TIMEOUT_DEFAULT)
                .requestReceiveInstant(Instant.now())
                .listener(listener)
                .build();
    }

    private Response buildResponse(final List<Violation> violations) {
        final Result result = Result.builder()
                .name("organizations/627849321070/locations/global/reports/e07358ef-cc8d-4834-a41e-6efcb8177251")
                .validationReport(IaCValidationReport.builder()
                        .violations(violations)
                        .note(DUMMY_NOTE)
                        .build())
                .createTime("2024-12-29T05:56:10.216565277Z")
                .updateTime("2024-12-29T05:56:10.216565277Z")
                .build();
        final OperationMetadata metadata = OperationMetadata.builder()
                .createTime("2024-01-05T08:42:02.325485680Z")
                .endTime("2024-01-05T08:42:02.473852683Z")
                .target("organizations/627849321070/locations/global/reports/142336eb-5c66-4283-bb3e-681595ac0644")
                .verb("create")
                .requestedCancellation(false)
                .apiVersion("v1")
                .build();
        return Response.builder()
                .name(
                        "organizations/627849321070/locations/global/operations/operation-1704444122295-60e2ed272ed68-625d72a8-6fd29abb")
                .done(true)
                .metadata(metadata)
                .result(result)
                .build();
    }
}
