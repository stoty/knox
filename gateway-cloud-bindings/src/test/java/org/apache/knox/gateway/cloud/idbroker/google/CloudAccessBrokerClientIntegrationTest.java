/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements. See the NOTICE file distributed with this
 * work for additional information regarding copyright ownership. The ASF
 * licenses this file to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */
package org.apache.knox.gateway.cloud.idbroker.google;

import com.google.cloud.hadoop.fs.gcs.GoogleHadoopFileSystem;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.fs.Path;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import java.net.URI;

import static org.junit.Assert.fail;

@RunWith(JUnit4.class)
public class CloudAccessBrokerClientIntegrationTest {

  /**
   * This test performs a knoxinit to establish the authentication token to be used for CloudAccessBroker interactions.
   *
   * The CloudAccessBrokerTokenProvider looks for this cached token, and uses it to ask the CAB for GCS credentials.
   */
  @Test
  public void testInitializeWithCloudAccessBroker() {
    final String myTestProject = "gcpidbroker";
    final String myTestBucket  = "gcsio-test_pzampino_0e6c1e4e_system";

    Configuration config = new Configuration();
    config.setBoolean("fs.gs.enable.service.account.auth", false);
    // Set project ID and client ID but no client secret.
    config.set("fs.gs.project.id", myTestProject);
    config.set("fs.gs.auth.client.id", "fooclient");

    // Configure the FS to use the CAB access token provider
    config.set("fs.gs.auth.access.token.provider.impl", CloudAccessBrokerTokenProvider.class.getName());

    // Tell the CAB access token provider where to find the CAB
    config.set(CloudAccessBrokerBindingConstants.CONFIG_CAB_ADDRESS, "https://localhost:8443/gateway/gcp-cab");

    // Tell the CAB access token provider where to find the CAB
    config.set(CloudAccessBrokerBindingConstants.CONFIG_DT_ADDRESS, "https://localhost:8443/gateway/dt");

    // Knox init
    try {
      CloudAccessBrokerClientTestUtils.knoxInit();
    } catch (Exception e) {
      fail(e.getMessage());
    }

    // Initialize the FS
    GoogleHadoopFileSystem ghfs = new GoogleHadoopFileSystem();
    try {
      ghfs.initialize(new URI("gs://" + myTestBucket + "/"), config);

      // Access the FS with the credentials from the CAB
      Path rootPath = ghfs.getFileSystemRoot();
      System.out.println("\n************************************************************");
      System.out.println("  GCS root path: " + rootPath.toString());
      System.out.println("************************************************************\n");

    } catch (Exception e) {
      fail(e.getMessage());
    } finally {
      try {
        CloudAccessBrokerClientTestUtils.restoreTokenCacheBackup();
      } catch (Exception e) {
        // Not really a big deal
      }
    }
  }

}
