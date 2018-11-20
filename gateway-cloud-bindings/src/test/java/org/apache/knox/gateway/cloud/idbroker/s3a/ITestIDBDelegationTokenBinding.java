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

import java.io.File;
import java.util.Date;

import org.junit.Test;
import org.junit.experimental.categories.Category;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.fs.s3a.S3AFileSystem;
import org.apache.hadoop.fs.s3a.auth.MarshalledCredentials;
import org.apache.hadoop.fs.s3a.auth.delegation.AbstractS3ATokenIdentifier;
import org.apache.hadoop.fs.s3a.auth.delegation.EncryptionSecrets;
import org.apache.hadoop.fs.s3a.auth.delegation.S3ADelegationTokens;
import org.apache.hadoop.io.IOUtils;
import org.apache.hadoop.io.Text;
import org.apache.hadoop.security.Credentials;
import org.apache.hadoop.security.token.Token;
import org.apache.hadoop.security.token.TokenIdentifier;
import org.apache.knox.test.category.VerifyTest;

import static java.util.Objects.requireNonNull;
import static org.apache.knox.gateway.cloud.idbroker.IDBConstants.DELEGATION_TOKEN_IDB_BINDING;
import static org.apache.knox.gateway.cloud.idbroker.IDBConstants.IDB_TOKEN_KIND;

/**
 * Binding handling.
 * {@see org.apache.hadoop.fs.s3a.auth.delegation.ITestSessionDelegationTokens}.
 */
@Category({VerifyTest.class})
public class ITestIDBDelegationTokenBinding extends AbstractStoreDelegationIT {

  protected static final Logger LOG =
      LoggerFactory.getLogger(ITestIDBDelegationTokenBinding.class);


  private S3ADelegationTokens delegationTokens;

  public Text getTokenKind() {
    return IDB_TOKEN_KIND;
  }

  @Override
  protected Configuration createConfiguration() {
    Configuration conf = super.createConfiguration();
    enableDelegationTokens(conf, DELEGATION_TOKEN_IDB_BINDING);
    return conf;
  }

  @Override
  public void setup() throws Exception {
    super.setup();
    resetUGI();
    Configuration conf = getConfiguration();
    S3AFileSystem fs = getFileSystem();
    delegationTokens = new S3ADelegationTokens();
    delegationTokens.bindToFileSystem(fs.getCanonicalUri(), fs);
    delegationTokens.init(conf);
    delegationTokens.start();
  }


  @Override
  public void teardown() throws Exception {
    IOUtils.cleanupWithLogger(LOG, delegationTokens);
    resetUGI();
    super.teardown();
  }

  @Test
  public void testSaveLoadTokens() throws Throwable {
    File tokenFile = File.createTempFile("token", "bin");
    Token<AbstractS3ATokenIdentifier> dt
        = delegationTokens.createDelegationToken(new EncryptionSecrets());
    final IDBS3ATokenIdentifier origIdentifier
        = (IDBS3ATokenIdentifier) dt.decodeIdentifier();
    
    assertEquals("kind in " + dt, getTokenKind(), dt.getKind());
    MarshalledCredentials marshalled
        = origIdentifier.getMarshalledCredentials();
    marshalled.validate("Created",
        MarshalledCredentials.CredentialTypeRequired.SessionOnly);
    long expiration = marshalled.getExpiration();
    Date expiryDate = new Date(expiration);
    Date currentDate = new Date(System.currentTimeMillis());
    String expires = String.format("%s (%d)", expiryDate, expiration);
    assertEquals("wrong month for " + expires,
        currentDate.getMonth(), expiryDate.getMonth());
    Configuration conf = getConfiguration();
    saveDT(tokenFile, dt);
    assertTrue("Empty token file", tokenFile.length() > 0);
    Credentials creds = Credentials.readTokenStorageFile(tokenFile, conf);
    Text serviceId = delegationTokens.getService();
    Token<? extends TokenIdentifier> token =
        requireNonNull(creds.getToken(serviceId),
            () -> "No token for \"" + serviceId + "\" in: "
                + creds.getAllTokens());
    IDBS3ATokenIdentifier dtId =
        (IDBS3ATokenIdentifier) token.decodeIdentifier();
    dtId.validate();
    assertEquals("token identifier ", origIdentifier, dtId);
    assertEquals("Origin in " + dtId,
        origIdentifier.getOrigin(), dtId.getOrigin());
  }

}
