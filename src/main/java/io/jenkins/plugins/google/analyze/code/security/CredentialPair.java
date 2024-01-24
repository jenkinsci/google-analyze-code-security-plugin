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

package io.jenkins.plugins.google.analyze.code.security;

import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.Extension;
import hudson.model.AbstractDescribableImpl;
import hudson.model.Descriptor;
import hudson.model.Item;
import hudson.util.FormValidation;
import hudson.util.Secret;
import io.jenkins.plugins.google.analyze.code.security.accessor.IACValidationService;
import io.jenkins.plugins.google.analyze.code.security.commons.CustomerMessage;
import io.jenkins.plugins.google.analyze.code.security.utils.ValidationUtils;
import java.io.Serializable;
import lombok.Data;
import lombok.EqualsAndHashCode;
import org.apache.commons.lang.StringUtils;
import org.kohsuke.stapler.AncestorInPath;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.DataBoundSetter;
import org.kohsuke.stapler.QueryParameter;
import org.kohsuke.stapler.verb.POST;
import org.springframework.security.access.AccessDeniedException;

/**
 * CredentialPair models Credential input from Jenkins UX.
 */
@EqualsAndHashCode(callSuper = true)
@Data
public class CredentialPair extends AbstractDescribableImpl<CredentialPair> implements Serializable {
    private String orgID;

    /**
     * <a href="https://www.jenkins.io/doc/developer/security/secrets/">Storing Secrets</a>
     */
    private Secret credential;

    @DataBoundSetter
    public void setOrgID(final String orgID) {
        this.orgID = orgID;
    }

    @DataBoundSetter
    public void setCredential(final Secret credential) {
        this.credential = credential;
    }

    @DataBoundConstructor
    public CredentialPair(final String orgID, final Secret credential) {
        this.credential = credential;
        this.orgID = orgID;
    }

    @Extension
    public static class DescriptorImpl extends Descriptor<CredentialPair> {

        /**
         * Validates OrgID is non-empty and contains numeric characters only.
         *
         * @param orgID GCP organizationId.
         * @param item Basic configuration unit in Hudson.
         * @return FormValidation
         */
        @POST
        public FormValidation doCheckOrgID(@QueryParameter final String orgID, @AncestorInPath final Item item) {
            ValidationUtils.checkPermissions(item);
            if (!ValidationUtils.isValidOrgId(orgID)) {
                return FormValidation.error(CustomerMessage.INVALID_ORG_ID);
            }
            return FormValidation.ok();
        }

        /**
         * Validate the credential pair by contacting the validation service.
         *
         * @param orgID GCP organizationId.
         * @param credential SCC credential corresponding to the orgID.
         * @return FormValidation
         */
        @POST
        public FormValidation doTestConnection(
                @QueryParameter("orgID") final String orgID,
                @QueryParameter("credential") final Secret credential,
                @AncestorInPath final Item item) {
            try {
                ValidationUtils.checkPermissions(item);
                IACValidationService.getInstance().validateCredentials(orgID, credential);
                return FormValidation.ok(CustomerMessage.VALID_CREDENTIAL_PAIR);
            } catch (AccessDeniedException ex) {
                return FormValidation.error(
                        String.format(CustomerMessage.INVALID_CREDENTIAL_INSUFFICIENT_PERMISSION, orgID));
            } catch (IllegalArgumentException ex) {
                return FormValidation.error(
                        String.format(CustomerMessage.CREDENTIAL_PAIR_VALIDATION_ERROR, ex.getMessage()));
            } catch (Exception ex) {
                return FormValidation.error(
                        String.format(CustomerMessage.CREDENTIAL_VALIDATION_INTERNAL_ERROR, ex.getMessage()));
            }
        }

        @NonNull
        public String getDisplayName() {
            return StringUtils.EMPTY;
        }
    }
}
