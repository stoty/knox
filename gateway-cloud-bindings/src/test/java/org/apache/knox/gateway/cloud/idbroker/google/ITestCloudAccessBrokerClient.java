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
import com.google.cloud.hadoop.fs.gcs.auth.GCSDelegationTokens;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.fs.LocatedFileStatus;
import org.apache.hadoop.fs.Path;
import org.apache.hadoop.fs.RemoteIterator;
import org.apache.hadoop.test.HadoopTestBase;
import org.apache.knox.test.category.VerifyTest;

import org.junit.Before;
import org.junit.Test;
import org.junit.experimental.categories.Category;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.URI;
import java.util.Date;

import static org.apache.knox.gateway.cloud.idbroker.IDBTestUtils.createTestConfiguration;
import static org.apache.knox.gateway.cloud.idbroker.google.CloudAccessBrokerClientTestUtils.*;

import static org.apache.knox.gateway.cloud.idbroker.google.CloudAccessBrokerBindingConstants.*;

@Category(VerifyTest.class)
@RunWith(JUnit4.class)
public class ITestCloudAccessBrokerClient extends HadoopTestBase {

  protected static final Logger LOG =
      LoggerFactory.getLogger(ITestCloudAccessBrokerClient.class);

  private Configuration config;

  @Before
  public void setup() {
    config = createTestConfiguration();
  }
  
  /**
   * This test performs a knoxinit to establish the authentication token to be used for CloudAccessBroker interactions.
   *
   * The CloudAccessBrokerTokenProvider looks for this cached token, and uses it to ask the CAB for GCS credentials.
   */
  @Test
  public void testInitializeWithCloudAccessBroker() throws Exception {

    final String myTestProject = requireTestProject(config);
    final String myTestBucket  = requireTestBucket(config);

    config.setBoolean("fs.gs.auth.service.account.enable", false);
    // Set project ID and client ID but no client secret.
    config.set(GoogleHadoopFileSystem.GCS_PROJECT_ID_KEY, myTestProject);
    config.set("fs.gs.auth.client.id", "fooclient");

    // If the client trust store is configured, apply it
    if (TRUST_STORE_LOCATION != null) {
      config.set(CONFIG_CAB_TRUST_STORE_LOCATION, TRUST_STORE_LOCATION);
    }

    // Configure the delegation token binding
    config.set(GCSDelegationTokens.CONFIG_DELEGATION_TOKEN_BINDING_CLASS,
               DELEGATION_TOKEN_BINDING);

    // Tell the CAB access token provider where to find the CAB
    config.set(CONFIG_CAB_ADDRESS, CLOUD_ACCESS_BROKER_ADDRESS);
    config.set(CONFIG_CAB_DT_PATH, DT_PATH);
    config.set(CONFIG_CAB_PATH, CAB_PATH);

    if (!CREDENTIAL_PROVIDER_PATH.isEmpty()) {
      config.set("hadoop.security.credential.provider.path", CREDENTIAL_PROVIDER_PATH);
    }

    // Knox init
    knoxInit(TRUST_STORE_LOCATION, TRUST_STORE_PASS);

    // Initialize the FS
    try(GoogleHadoopFileSystem ghfs = new GoogleHadoopFileSystem()) {
      ghfs.initialize(new URI(myTestBucket), config);

      // Access the FS with the credentials from the CAB
      Path rootPath = ghfs.getFileSystemRoot();
      LOG.info("GCS root path: {}", rootPath.toString());

      RemoteIterator<LocatedFileStatus> fileStatusIter = ghfs.listFiles(ghfs.getFileSystemRoot(), false);
      assertNotNull(fileStatusIter);
      while (fileStatusIter.hasNext()) {
        LocatedFileStatus fs = fileStatusIter.next();
        LOG.info(fs.getPermission() + " " +
                 fs.getOwner() + " " +
                 fs.getGroup() + " " +
                 fs.getLen() + " " +
                 new Date(fs.getModificationTime()) + " " +
                 fs.getPath());
      }

    } finally {
      try {
        restoreTokenCacheBackup();
      } catch (Exception e) {
        // Not really a big deal
      }
    }
  }

}
