/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.knox.gateway.service.idbroker;

import org.apache.knox.gateway.service.idbroker.azure.KnoxAzureClient;
import org.junit.Test;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

public class KnoxAzureClientTest {

  public static final String MSI_PASS_1 = "/subscriptions/cff0e60e-1029-4be1-ba99-063347c927ce/resourcegroups/ADLSGen2-smore/providers/Microsoft.ManagedIdentity/userAssignedIdentities/contributor_msi";
  public static final String MSI_PASS_2 = "/subscriptions/82a95411-be37-4c8b-832b-a68bf5cc2c88/resourceGroups/ashukla-dl8296/providers/Microsoft.ManagedIdentity/userAssignedIdentities/test-contributor-msi";
  public static final String MSI_PASS_3 = "subscriptions/4596e1fd-3daf-4e3a-a3f8-6f463d419b0b/resourceGroups/ashukla-dl8296/providers/Microsoft.ManagedIdentity/userAssignedIdentities/test-contributor-msi";
  public static final String MSI_FAIL = "/subscriptions/5c378889-2bd7-495d-965b-fff888a6654e/resourcegroups/ADLSGen2-smore/providers/userAssignedIdentities/contributor_msi";
  public static Pattern MSI_PATTERN = Pattern.compile(KnoxAzureClient.MSI_PATH_REGEX_NAMED);

  /**
   * test to check MSI name pattern used to validate MSI names.
   */
  @Test
  public void testMSITokenNamePattern() {
    /* test for resourcegroup */
    Matcher matcher = KnoxAzureClient.MSI_PATH_PATTERN.matcher(MSI_PASS_1);
    if(matcher.matches()) {
      assertEquals("cff0e60e-1029-4be1-ba99-063347c927ce", matcher.group("subscription"));
      assertEquals("ADLSGen2-smore", matcher.group("resourceGroup"));
      assertEquals("contributor_msi", matcher.group("vmName"));
    } else {
      fail("No Match found");
    }

    /* test for resourceGroup */
    matcher = KnoxAzureClient.MSI_PATH_PATTERN.matcher(MSI_PASS_2);
    if(matcher.matches()) {
      assertEquals("82a95411-be37-4c8b-832b-a68bf5cc2c88", matcher.group("subscription"));
      assertEquals("ashukla-dl8296", matcher.group("resourceGroup"));
      assertEquals("test-contributor-msi", matcher.group("vmName"));
    } else {
      fail("No Match found");
    }

    /* test for subscription without forward / */
    matcher = KnoxAzureClient.MSI_PATH_PATTERN.matcher(MSI_PASS_3);
    if(matcher.matches()) {
      assertEquals("4596e1fd-3daf-4e3a-a3f8-6f463d419b0b", matcher.group("subscription"));
      assertEquals("ashukla-dl8296", matcher.group("resourceGroup"));
      assertEquals("test-contributor-msi", matcher.group("vmName"));
    } else {
      fail("No Match found");
    }

    /* test for invalid MSI name  */
    matcher = KnoxAzureClient.MSI_PATH_PATTERN.matcher(MSI_FAIL);
    if(matcher.matches()) {
      fail("Matched invalid name");
    }

  }

}
