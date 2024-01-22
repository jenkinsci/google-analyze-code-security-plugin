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

package io.jenkins.plugins.google.analyze.code.security.commons;

import hudson.FilePath;
import io.jenkins.plugins.google.analyze.code.security.model.IACValidationService.response.AssetDetails;
import io.jenkins.plugins.google.analyze.code.security.model.IACValidationService.response.PolicyDetails;
import io.jenkins.plugins.google.analyze.code.security.model.IACValidationService.response.PostureDetails;
import io.jenkins.plugins.google.analyze.code.security.model.IACValidationService.response.Severity;
import io.jenkins.plugins.google.analyze.code.security.model.IACValidationService.response.Violation;

import java.io.File;
import java.util.List;

/**
 * TestUtil contains helper methods & constants for test.
 */
public final class TestUtil {
    private TestUtil() {}
    public static final String DUMMY_ORG_ID = "777838403257";
    public static final String DUMMY_VALIDATE_FILE_PATH  = "/dummyValidateFilePath";
    public static final String DUMMY_SCAN_START_TIME = "05 01 2024 08:42:00";
    public static final String DUMMY_SCAN_END_TIME = "05 01 2024 08:42:04";
    public static final FilePath DUMMY_FILE_PATH =  new FilePath(new File("test"));
    public static final List<Violation> DUMMY_VIOLATIONS = List.of(
            Violation.builder()
                    .assetId("storage.googleapis.com/buckets/b1")
                    .policyId("folders/123456/policies/custom.publicBucketACL")
                    .severity(Severity.CRITICAL)
                    .nextSteps("You can fix this by following Step 1, Step 2 and Step 3")
                    .violatedPosture(PostureDetails.builder()
                            .postureDeployment("organizations/777838403257/locations/global/postureDeployments/pd1")
                            .postureDeploymentTargetResource("folders/123456")
                            .posture("organizations/777838403257/locations/global/postures/posture1")
                            .postureRevisionId("rev1")
                            .policySet("my-policy-set-1")
                            .build())
                    .violatedAsset(AssetDetails.builder()
                            .asset("some json representation of asset")
                            .assetType("storage.googleapis.com/Bucket")
                            .build())
                    .violatedPolicy(PolicyDetails.builder()
                            .constraint("some json representation of constraint")
                            .constraintType("ORG_POLICY_CUSTOM")
                            .complianceStandards(List.of("CIS 2.0 1.15", "NIST 1.5"))
                            .description("detailed description")
                            .build())
                    .build(),
            Violation.builder()
                    .assetId("storage.googleapis.com/buckets/b2")
                    .policyId("folders/123456/policies/custom.uniformBucketLevelAccess")
                    .severity(Severity.LOW)
                    .violatedPolicy(PolicyDetails.builder()
                            .constraint("some json representation of constraint")
                            .constraintType("ORG_POLICY_CUSTOM")
                            .complianceStandards(List.of("NIST 3"))
                            .description("detailed description")
                            .build())
                    .build(),
            Violation.builder()
                    .assetId("storage.googleapis.com/buckets/b3")
                    .policyId("folders/123456/policies/custom.uniformBucketLevelAccess")
                    .severity(Severity.LOW)
                    .build()
    );
}
