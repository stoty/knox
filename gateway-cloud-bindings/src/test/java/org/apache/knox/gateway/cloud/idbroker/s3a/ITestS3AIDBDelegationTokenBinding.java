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
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Instant;
import java.time.LocalDateTime;
import java.util.Locale;

import org.junit.Test;
import org.junit.experimental.categories.Category;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import software.amazon.awssdk.auth.credentials.AwsSessionCredentials;

import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.fs.s3a.AWSCredentialProviderList;
import org.apache.hadoop.fs.s3a.S3AEncryptionMethods;
import org.apache.hadoop.fs.s3a.S3AFileSystem;
import org.apache.hadoop.fs.s3a.auth.MarshalledCredentials;
import org.apache.hadoop.fs.s3a.auth.delegation.AbstractDTService;
import org.apache.hadoop.fs.s3a.auth.delegation.AbstractS3ATokenIdentifier;
import org.apache.hadoop.fs.s3a.auth.delegation.EncryptionSecrets;
import org.apache.hadoop.fs.s3a.auth.delegation.S3ADelegationTokens;
import org.apache.hadoop.io.IOUtils;
import org.apache.hadoop.io.Text;
import org.apache.hadoop.security.Credentials;
import org.apache.hadoop.security.authentication.util.KerberosUtil;
import org.apache.hadoop.security.token.SecretManager;
import org.apache.hadoop.security.token.Token;
import org.apache.hadoop.security.token.TokenIdentifier;
import org.apache.knox.gateway.shell.KnoxShellException;
import org.apache.knox.test.category.VerifyTest;

import static java.util.Objects.requireNonNull;
import static org.apache.hadoop.test.GenericTestUtils.assertExceptionContains;
import static org.apache.hadoop.test.LambdaTestUtils.intercept;
import static org.apache.knox.gateway.cloud.idbroker.s3a.IDBS3AConstants.IDB_TOKEN_KIND;
import static org.apache.knox.gateway.cloud.idbroker.IDBTestUtils.assertNotEmptyString;
import static org.apache.knox.gateway.cloud.idbroker.s3a.S3AIDBProperty.IDBROKER_INIT_CAB_CREDENTIALS;
import static org.junit.Assume.assumeNotNull;

/**
 * Binding handling.
 * {@see org.apache.hadoop.fs.s3a.auth.delegation.ITestSessionDelegationTokens}.
 */
@Category(VerifyTest.class)
public class ITestS3AIDBDelegationTokenBinding
    extends AbstractStoreDelegationIT {

  protected static final Logger LOG =
      LoggerFactory.getLogger(ITestS3AIDBDelegationTokenBinding.class);


  private S3ADelegationTokens delegationTokens;

  public Text getTokenKind() {
    return IDB_TOKEN_KIND;
  }

  @Override
  protected Configuration createConfiguration() {
    Configuration conf = super.createConfiguration();
    enableDelegationTokens(conf, IDBDelegationTokenBinding.class.getName());
    return conf;
  }

  @Override
  public void setup() throws Exception { //NOPMD
    // Skip test if /etc/krb5.conf isn't present
    assumeNotNull(KerberosUtil.getDefaultRealmProtected());

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
  public void teardown() throws Exception { //NOPMD
    IOUtils.cleanupWithLogger(LOG, delegationTokens);
    resetUGI();
    super.teardown();
  }

  @Test
  public void testSaveLoadTokens() throws Throwable {
    Token<AbstractS3ATokenIdentifier> dt
        = delegationTokens.createDelegationToken(new EncryptionSecrets(), null);
    final IDBS3ATokenIdentifier origIdentifier
        = (IDBS3ATokenIdentifier) dt.decodeIdentifier();

    assertEquals("kind in " + dt, getTokenKind(), dt.getKind());
    MarshalledCredentials marshalled
        = origIdentifier.getMarshalledCredentials();
    marshalled.validate("Created",
        MarshalledCredentials.CredentialTypeRequired.SessionOnly);
    long expiration = marshalled.getExpiration();
    LocalDateTime expiryDate = LocalDateTime.from(Instant.ofEpochMilli(expiration));
    LocalDateTime currentDate = LocalDateTime.now(Clock.systemDefaultZone());
    String expires = String.format(Locale.ROOT, "%s (%d)", expiryDate, expiration);
    assertEquals("wrong month for " + expires,
        currentDate.getMonth(), expiryDate.getMonth());
    final Text serviceId = delegationTokens.getService();
    IDBS3ATokenIdentifier dtId = extractTokenIdentifier(
        saveAndLoad(tempTokenFile(), dt, getConfiguration()), serviceId);
    assertEquals("token identifier ", origIdentifier, dtId);
    // save the string for reuse across assertions
    final String dts = dtId.toString();
    assertEquals("Origin in " + dts,
        origIdentifier.getOrigin(), dtId.getOrigin());
    assertNotEmptyString("Certificate in " + dts, dtId.getCertificate());
  }

  private File tempTokenFile() throws IOException {
    return File.createTempFile("token", "bin");
  }

  private IDBS3ATokenIdentifier extractTokenIdentifier(final Credentials creds,
      final Text serviceId) throws IOException {
    Token<? extends TokenIdentifier> token =
        requireNonNull(creds.getToken(serviceId),
            () -> "No token for \"" + serviceId + "\" in: "
                + creds.getAllTokens());
    IDBS3ATokenIdentifier dtId =
        (IDBS3ATokenIdentifier) token.decodeIdentifier();
    dtId.validate();
    return dtId;
  }

  private Credentials saveAndLoad(final File tokenFile,
      final Token<AbstractS3ATokenIdentifier> dt,
      final Configuration conf)
      throws IOException {
    saveDT(tokenFile, dt);
    assertTrue("Empty token file", tokenFile.length() > 0);
    return Credentials.readTokenStorageFile(tokenFile, conf);
  }

  @Test
  public void testIssueTokensWithoutAWSSecrets() throws Throwable {
    describe("Issue tokens without any AWS secrets to verify workflow");
    Configuration conf = new Configuration(getConfiguration());
    IDBS3ATokenIdentifier identifier;
    conf.setBoolean(IDBROKER_INIT_CAB_CREDENTIALS.getPropertyName(), false);
    try (S3ADelegationTokens tokens2 = new S3ADelegationTokens()) {
      bindToClusterFS(conf, tokens2);
      EncryptionSecrets encryptionSecrets =
          new EncryptionSecrets(S3AEncryptionMethods.SSE_KMS,
              "arn:kms:testIssueTokensWithoutAWSSecrets)");
      Token<AbstractS3ATokenIdentifier> dt
          = tokens2.createDelegationToken(encryptionSecrets, null);
      identifier = (IDBS3ATokenIdentifier) dt.decodeIdentifier();
      assertEquals("Marshalled Encryption", encryptionSecrets,
          identifier.getEncryptionSecrets());
      String ids = identifier.toString();
      assertFalse("AWS credentials found in " + ids,
          identifier.hasMarshalledCredentials());
      MarshalledCredentials awsSecrets
          = identifier.getMarshalledCredentials();
      assertEquals("Marshalled credentials are not empty in " + ids,
          MarshalledCredentials.empty(), awsSecrets);
      // now check unmarshalling logic can handle this situation
      assertNull("Extracted IDB credentials from " + ids,
          IDBDelegationTokenBinding.extractMarshalledCredentials(identifier));
    }

    // now, without a token, a new AbstractIDBClient instance should be able to
    // talk to IDBroker and retrieve some new ones
    try (IDBDelegationTokenBinding tokenBinding = new IDBDelegationTokenBinding()) {
      bindToClusterFS(conf, tokenBinding);
      // bind to the issued DT identifier, the one without any credentials
      AWSCredentialProviderList providerList
          = tokenBinding.bindToTokenIdentifier(identifier);
      // this forces token collection
      AwsSessionCredentials credentials = (AwsSessionCredentials)
          providerList.resolveCredentials();
      assertNotEmptyString("access key",
          credentials.accessKeyId());
      assertNotEmptyString("secret key",
          credentials.secretAccessKey());
      assertNotEmptyString("session token",
          credentials.sessionToken());
    }
  }

  /**
   * This is an implicit way to verify that the certificate in the DT is
   * the one used to connect to Knox: if the certificate in a token is
   * invalid, then the attempt to retrieve new AWS credentials MUST fail.
   */
  @Test
  public void testIssueTokensUseCertificates() throws Throwable {
    describe("Create an identifier with an invalid token,"
        + " verify that AWS credential retrieval fails ");
    Configuration conf = new Configuration(getConfiguration());
    IDBS3ATokenIdentifier badCertIdentifier;
    conf.setBoolean(IDBROKER_INIT_CAB_CREDENTIALS.getPropertyName(), false);
    try (S3ADelegationTokens tokens2 = new S3ADelegationTokens()) {
      bindToClusterFS(conf, tokens2);
      EncryptionSecrets encryptionSecrets =
          new EncryptionSecrets(S3AEncryptionMethods.SSE_C,
              "1");
      Token<AbstractS3ATokenIdentifier> dt
          = tokens2.createDelegationToken(encryptionSecrets, null);
      IDBS3ATokenIdentifier identifier
          = (IDBS3ATokenIdentifier) dt.decodeIdentifier();
      assertFalse("AWS credentials found in " + identifier,
          identifier.hasMarshalledCredentials());
      // build an identifier with a bad certificate
      final String certificate = identifier.getCertificate();
      String invalidCert = certificate.substring(0, certificate.length() - 8);
      IDBS3ATokenIdentifier id3 = new IDBS3ATokenIdentifier(
          IDB_TOKEN_KIND,
          identifier.getOwner(),
          null,
          identifier.getUri(),
          identifier.getAccessToken(),
          identifier.getExpiryTime(),
          MarshalledCredentials.empty(),
          identifier.getEncryptionSecrets(),
          "",
          identifier.getOrigin(),
          identifier.getIssueDate(),
          identifier.getTrackingId(),
          identifier.getEndpoint(),
          invalidCert,
          true);
      // save and load it to guarantee everything works through the round trip.
      Token<AbstractS3ATokenIdentifier> invalidToken
          = new Token<>(id3, new TokenSecretManager());
      badCertIdentifier = extractTokenIdentifier(
          saveAndLoad(tempTokenFile(), invalidToken, getConfiguration()),
          invalidToken.getService());
    }

    // use the bad certificate and expect token retrieval to fail.
    // this verifies that the certificate in the token is being used
    // to request the token, irrespective of any other setting
    try (IDBDelegationTokenBinding tokenBinding = new IDBDelegationTokenBinding()) {
      bindToClusterFS(conf, tokenBinding);
      // knox shell failure
      KnoxShellException ex = intercept(
          KnoxShellException.class,
          "Failed to create HTTP client",
          () -> tokenBinding.bindToTokenIdentifier(badCertIdentifier));

      // with inner text about certificate
      assertExceptionContains(
          "certificate", ex.getCause());
    }
  }

  /**
   * Bind any S3A DT service to a filesystem.
   * @param conf configuration to use.
   * @param dtService service
   * @throws IOException failure
   */
  private void bindToClusterFS(final Configuration conf,
      final AbstractDTService dtService) throws IOException {
    S3AFileSystem fs = getFileSystem();
    dtService.bindToFileSystem(fs.getCanonicalUri(), fs);
    dtService.init(conf);
    dtService.start();
  }

  /**
   * Get the password to use in secret managers.
   * This is a constant; its just recalculated every time to stop findbugs
   * highlighting security risks of shared mutable byte arrays.
   * @return a password.
   */

  protected static byte[] getSecretManagerPassword() {
    return "non-password".getBytes(StandardCharsets.UTF_8);
  }

  /**
   * The secret manager always uses the same secret; the
   * factory for new identifiers is that of the token manager.
   */
  protected class TokenSecretManager
      extends SecretManager<AbstractS3ATokenIdentifier> {

    @Override
    protected byte[] createPassword(AbstractS3ATokenIdentifier identifier) {
      return getSecretManagerPassword();
    }

    @Override
    public byte[] retrievePassword(AbstractS3ATokenIdentifier identifier) {
      return getSecretManagerPassword();
    }

    @Override
    public AbstractS3ATokenIdentifier createIdentifier() {
      return new IDBS3ATokenIdentifier();
    }
  }
}
