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

package org.apache.knox.gateway.cloud.idbroker.s3a;

import java.io.IOException;
import java.net.URI;

import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.apache.commons.lang3.StringUtils;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.fs.FileStatus;
import org.apache.hadoop.fs.FileSystem;
import org.apache.hadoop.fs.Path;
import org.apache.hadoop.fs.s3a.Constants;
import org.apache.hadoop.fs.s3a.S3AFileSystem;
import org.apache.hadoop.fs.s3a.auth.MarshalledCredentials;
import org.apache.hadoop.fs.s3a.auth.delegation.DelegationConstants;
import org.apache.hadoop.fs.s3a.commit.DurationInfo;
import org.apache.hadoop.io.IOUtils;
import org.apache.knox.gateway.cloud.idbroker.IDBAWSCredentialProvider;
import org.apache.knox.gateway.cloud.idbroker.IDBClient;
import org.apache.knox.gateway.cloud.idbroker.IDBConstants;
import org.apache.knox.gateway.cloud.idbroker.commands.FetchIDBToken;

import static org.apache.hadoop.test.LambdaTestUtils.intercept;
import static org.apache.knox.gateway.cloud.idbroker.IDBConstants.IDBROKER_TOKEN;

/**
 * Test the simple IDB AWS auth provider
 */
public class ITestIDBClientAWSAuthProvider extends AbstractS3AStoreTest {

  protected static final Logger LOG =
      LoggerFactory.getLogger(ITestIDBClientAWSAuthProvider.class);

  private IDBClient client;

  @Override
  public void setup() throws Exception {
    client = new IDBClient(IDBConstants.LOCAL_GATEWAY,
        IDBConstants.DEFAULT_CERTIFICATE_PATH,
        IDBConstants.DEFAULT_CERTIFICATE_PASSWORD);
    super.setup();
  }

  @Test
  public void testFetchAccessToken() throws Throwable {
    assertTrue(StringUtils.isNotEmpty(fetchAdminToken(client)));
  }

  protected String fetchAdminToken(final IDBClient client) throws IOException {
    String token = client.requestKnoxDelegationToken(
        client.knoxDtSession(IDBConstants.ADMIN_USER,
            IDBConstants.ADMIN_PASSWORD)).access_token;
    LOG.info("Retrieved token: {}", token);
    return token;
  }

  @Test
  public void testChainedLogin() throws Throwable {
    String token = fetchAdminToken(client);
    MarshalledCredentials awsCredentials = client.fetchAWSCredentials(
        client.cloudSessionFromDT(token));
    assertNotNull(awsCredentials.toAWSCredentials(
        MarshalledCredentials.CredentialTypeRequired.SessionOnly));
  }


  @Test
  public void testAWSAccessProviderLifecycle() throws Throwable {
    String token = fetchAdminToken(client);
    S3AFileSystem fs = getFileSystem();
    Configuration conf = fs.getConf();
    conf.set(IDBROKER_TOKEN, token);
    URI uri = fs.getUri();
    IDBAWSCredentialProvider provider
        = new IDBAWSCredentialProvider(uri, conf);
    provider.getCredentials();
    provider.refresh();
    provider.close();
  }

  @Test
  public void testFileSystemCreation() throws Throwable {
    S3AFileSystem fs = getFileSystem();
    String token = fetchAdminToken(client);
    // clear these to ensure really clear
    Configuration conf = fs.getConf();
    conf.unset(Constants.ACCESS_KEY);
    conf.unset(Constants.SECRET_KEY);
    conf.unset(Constants.SESSION_TOKEN);
    //patch in the credential provider
    conf.set(Constants.AWS_CREDENTIALS_PROVIDER, IDBAWSCredentialProvider.NAME);
    conf.set(IDBROKER_TOKEN, token);
    URI uri = fs.getUri();
    S3AFileSystem s3aFS = null;
    try (DurationInfo ignored = new DurationInfo(LOG,
        "Creating new S3A Filesystem")) {
      s3aFS = (S3AFileSystem) FileSystem.newInstance(uri, conf);
    }
    try {
      LOG.info("Created new filesystem {}", s3aFS);
      FileStatus[] statuses = s3aFS.listStatus(new Path("/"));
      for (FileStatus status : statuses) {
        LOG.info("{}", status.getPath());
      }

    } finally {
      IOUtils.cleanupWithLogger(LOG, s3aFS);
    }
  }

  @Test
  public void testFileSystemCreationNoToken() throws Throwable {
    describe("Create a file without any token and expect a failure");
    S3AFileSystem fs = getFileSystem();
    Configuration conf = fs.getConf();
    conf.unset(Constants.ACCESS_KEY);
    conf.unset(Constants.SECRET_KEY);
    conf.unset(Constants.SESSION_TOKEN);
    //patch in the credential provider
    conf.unset(DelegationConstants.DELEGATION_TOKEN_BINDING);
    conf.set(Constants.AWS_CREDENTIALS_PROVIDER, IDBAWSCredentialProvider.NAME);
    conf.unset(IDBROKER_TOKEN);
    URI uri = fs.getUri();
    intercept(IOException.class, IDBROKER_TOKEN,
        () -> FileSystem.newInstance(uri, conf));
  }

  @Test
  public void testFetchIDBToken() throws Throwable {
    FetchIDBToken.exec();
  }

}
