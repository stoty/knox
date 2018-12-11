/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements. See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership. The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
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
import java.net.URI;

import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.experimental.categories.Category;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.fs.FileSystem;
import org.apache.hadoop.fs.Path;
import org.apache.hadoop.fs.contract.ContractTestUtils;
import org.apache.hadoop.fs.s3a.S3AEncryptionMethods;
import org.apache.hadoop.fs.s3a.S3AFileSystem;
import org.apache.hadoop.fs.s3a.Statistic;
import org.apache.hadoop.fs.s3a.auth.delegation.AbstractS3ATokenIdentifier;
import org.apache.hadoop.fs.s3a.auth.delegation.S3ADelegationTokens;
import org.apache.hadoop.hdfs.tools.DelegationTokenFetcher;
import org.apache.hadoop.io.Text;
import org.apache.hadoop.mapreduce.security.TokenCache;
import org.apache.hadoop.security.Credentials;
import org.apache.hadoop.security.UserGroupInformation;
import org.apache.hadoop.security.token.Token;
import org.apache.hadoop.service.ServiceOperations;
import org.apache.hadoop.util.ExitUtil;
import org.apache.hadoop.yarn.conf.YarnConfiguration;
import org.apache.knox.gateway.cloud.idbroker.IDBConstants;
import org.apache.knox.gateway.cloud.idbroker.IDBTestUtils;
import org.apache.knox.gateway.cloud.idbroker.MiniIDBHadoopCluster;
import org.apache.knox.test.category.VerifyTest;

import static java.util.Objects.requireNonNull;
import static org.apache.hadoop.fs.CommonConfigurationKeysPublic.HADOOP_SECURITY_AUTHENTICATION;
import static org.apache.hadoop.fs.s3a.Constants.ACCESS_KEY;
import static org.apache.hadoop.fs.s3a.Constants.AWS_CREDENTIALS_PROVIDER;
import static org.apache.hadoop.fs.s3a.Constants.SECRET_KEY;
import static org.apache.hadoop.fs.s3a.Constants.SERVER_SIDE_ENCRYPTION_ALGORITHM;
import static org.apache.hadoop.fs.s3a.Constants.SESSION_TOKEN;
import static org.apache.hadoop.fs.s3a.auth.delegation.DelegationConstants.DELEGATION_TOKEN_ENDPOINT;
import static org.apache.hadoop.fs.s3a.auth.delegation.DelegationConstants.DELEGATION_TOKEN_ROLE_ARN;
import static org.apache.hadoop.fs.s3a.auth.delegation.S3ADelegationTokens.lookupS3ADelegationToken;
import static org.apache.hadoop.test.LambdaTestUtils.doAs;
import static org.apache.knox.gateway.cloud.idbroker.IDBTestUtils.disableFilesystemCaching;
import static org.apache.knox.gateway.cloud.idbroker.IDBTestUtils.removeBaseAndBucketOverrides;
import static org.apache.knox.gateway.cloud.idbroker.IDBTestUtils.unsetHadoopCredentialProviders;
import static org.apache.knox.gateway.cloud.idbroker.MiniIDBHadoopCluster.ALICE;
import static org.hamcrest.collection.IsCollectionWithSize.hasSize;

/**
 * Tests use of Hadoop delegation tokens within the FS itself.
 * This instantiates a MiniKDC as some of the operations tested require
 * UGI to be initialized with security enabled.
 *
 * See
 * {@code org.apache.hadoop.fs.s3a.auth.delegation.ITestSessionDelegationInFileystem}
 */
@SuppressWarnings("StaticNonFinalField")
@Category(VerifyTest.class)
public class ITestIDBDelegationInFileystem extends AbstractStoreDelegationIT {

  private static final Logger LOG =
      LoggerFactory.getLogger(ITestIDBDelegationInFileystem.class);

  private static MiniIDBHadoopCluster cluster;

  private UserGroupInformation bobUser;

  private UserGroupInformation aliceUser;

  private S3ADelegationTokens delegationTokens;

  /***
   * Set up a mini cluster instance with users in the keytab.
   */
  @BeforeClass
  public static void setupCluster() throws Exception {
    cluster = new MiniIDBHadoopCluster();
    cluster.init(new Configuration());
    cluster.start();
  }

  /**
   * Tear down the cluster.
   */
  @SuppressWarnings("ThrowableNotThrown")
  @AfterClass
  public static void teardownCluster() throws Exception {
    ServiceOperations.stopQuietly(LOG, cluster);
  }

  protected static MiniIDBHadoopCluster getCluster() {
    return cluster;
  }

  /**
   * Get the delegation token binding for this test suite.
   * @return which DT binding to use.
   */
  protected String getDelegationBinding() {
    return IDBConstants.DELEGATION_TOKEN_IDB_BINDING;
  }

  /**
   * Get the kind of the tokens which are generated.
   * @return the kind of DT
   */
  public Text getTokenKind() {
    return IDBConstants.IDB_TOKEN_KIND;
  }

  @Override
  protected Configuration createConfiguration() {
    Configuration conf = super.createConfiguration();
    // disable if assume role opts are off
    disableFilesystemCaching(conf);
    conf.set(HADOOP_SECURITY_AUTHENTICATION,
        UserGroupInformation.AuthenticationMethod.KERBEROS.name());
    enableDelegationTokens(conf, getDelegationBinding());
    conf.set(AWS_CREDENTIALS_PROVIDER, " ");
    // switch to SSE_S3.
    conf.set(SERVER_SIDE_ENCRYPTION_ALGORITHM,
        S3AEncryptionMethods.SSE_S3.getMethod());
    // set the YARN RM up for YARN tests.
    conf.set(YarnConfiguration.RM_PRINCIPAL, YARN_RM);
    return conf;
  }


  @Override
  public void setup() throws Exception {
    // clear any existing tokens from the FS
    resetUGI();
    UserGroupInformation.setConfiguration(createConfiguration());

    aliceUser = cluster.createAliceUser();
    bobUser = cluster.createBobUser();

    UserGroupInformation.setLoginUser(aliceUser);
    // only now do the setup, so that any FS created is secure
    super.setup();
    S3AFileSystem fs = getFileSystem();
    // make sure there aren't any tokens
    assertNull("Unexpectedly found an S3A token",
        lookupS3ADelegationToken(
            UserGroupInformation.getCurrentUser().getCredentials(),
            fs.getUri()));

    // DTs are inited but not started.
    delegationTokens = instantiateDTSupport(getConfiguration());
  }

  @SuppressWarnings("ThrowableNotThrown")
  @Override
  public void teardown() throws Exception {
    super.teardown();
    ServiceOperations.stopQuietly(LOG, delegationTokens);
    FileSystem.closeAllForUGI(UserGroupInformation.getCurrentUser());
    cluster.closeUserFileSystems(aliceUser);
    cluster.closeUserFileSystems(bobUser);
    cluster.resetUGI();
  }

  @Test
  public void testGetDTfromFileSystem() throws Throwable {
    describe("Enable delegation tokens and request one");
    delegationTokens.start();
    S3AFileSystem fs = getFileSystem();
    IDBTestUtils.MetricDiff invocationDiff = new IDBTestUtils.MetricDiff(fs,
        Statistic.INVOCATION_GET_DELEGATION_TOKEN);
    IDBTestUtils.MetricDiff issueDiff = new IDBTestUtils.MetricDiff(fs,
        Statistic.DELEGATION_TOKENS_ISSUED);
    Token<AbstractS3ATokenIdentifier> token =
        requireNonNull(fs.getDelegationToken(""),
            "no token from filesystem " + fs);
    assertEquals("token kind", getTokenKind(), token.getKind());
    assertTokenCreationCount(fs, 1);
    final String fsInfo = fs.toString();
    invocationDiff.assertDiffEquals("getDelegationToken() in " + fsInfo,
        1);
    issueDiff.assertDiffEquals("DTs issued in " + delegationTokens,
        1);

    Text service = delegationTokens.getService();
    assertEquals("service name", service, token.getService());
    Credentials creds = new Credentials();
    creds.addToken(service, token);
    assertEquals("retrieve token from " + creds,
        token, creds.getToken(service));
  }

  @Test
  public void testCanRetrieveTokenFromCurrentUserCreds() throws Throwable {
    describe("Create a DT, add it to the current UGI credentials,"
        + " then retrieve");
    delegationTokens.start();
    Credentials cred = createDelegationTokens();
    UserGroupInformation ugi = UserGroupInformation.getCurrentUser();
    ugi.addCredentials(cred);
    Token<?>[] tokens = cred.getAllTokens().toArray(new Token<?>[0]);
    Token<?> token0 = tokens[0];
    Text service = token0.getService();
    LOG.info("Token = " + token0);
    Token<?> token1 = requireNonNull(
        ugi.getCredentials().getToken(service), "Token from " + service);
    assertEquals("retrieved token", token0, token1);
    assertNotNull("token identifier of " + token1,
        token1.getIdentifier());
  }

  @Test
  public void testDTCredentialProviderFromCurrentUserCreds() throws Throwable {
    describe("Add credentials to the current user, "
        + "then verify that they can be found when S3ADelegationTokens binds");
    Credentials cred = createDelegationTokens();
    assertThat("Token size", cred.getAllTokens(), hasSize(1));
    UserGroupInformation.getCurrentUser().addCredentials(cred);
    delegationTokens.start();
    assertTrue("bind to existing DT failed",
        delegationTokens.isBoundToDT());
  }

  /**
   * Create credentials with the DTs of the current FS.
   * @return a non-empty set of credentials.
   * @throws IOException failure to create.
   */
  protected Credentials createDelegationTokens() throws IOException {
    return mkTokens(getFileSystem());
  }

  /**
   * Create a FS with a delegated token, verify it works as a filesystem,
   * and that you can pick up the same DT from that FS too.
   */
  @Test
  public void testDelegatedFileSystem() throws Throwable {
    describe("Delegation tokens can be passed to a new filesystem;"
        + " if role restricted, permissions are tightened.");
    S3AFileSystem fs = getFileSystem();

    URI uri = fs.getUri();
    // create delegation tokens from the test suites FS.
    Credentials creds = createDelegationTokens();
    final Text tokenKind = getTokenKind();
    AbstractS3ATokenIdentifier origTokenId = requireNonNull(
        lookupToken(
            creds,
            uri,
            tokenKind),
        "original");
    // attach to the user, so that when tokens are looked for, they get picked
    // up
    final UserGroupInformation currentUser
        = UserGroupInformation.getCurrentUser();
    currentUser.addCredentials(creds);
    // verify that the tokens went over
    requireNonNull(lookupToken(
        currentUser.getCredentials(),
        uri,
        tokenKind),
        "lookup token in user credentials");
    Configuration conf = new Configuration(getConfiguration());
    String bucket = fs.getBucket();
    disableFilesystemCaching(conf);
    unsetHadoopCredentialProviders(conf);
    // remove any secrets we don't want the delegated FS to accidentally
    // pick up.
    // this is to simulate better a remote deployment.
    removeBaseAndBucketOverrides(bucket, conf,
        ACCESS_KEY, SECRET_KEY, SESSION_TOKEN,
        SERVER_SIDE_ENCRYPTION_ALGORITHM,
        DELEGATION_TOKEN_ROLE_ARN,
        DELEGATION_TOKEN_ENDPOINT);
    // this is done to make sure you cannot create an STS session no
    // matter how you pick up credentials.
    conf.set(DELEGATION_TOKEN_ENDPOINT, "http://localhost:8080/");

    // create a new FS instance, which is expected to pick up the
    // existing token
    Path testPath = path("testDTFileSystemClient");
    try (S3AFileSystem delegatedFS = newS3AInstance(uri, conf)) {
      LOG.info("Delegated filesystem is: {}", delegatedFS);
      assertBoundToDT(delegatedFS, tokenKind);
      assertEquals("Encryption propagation failed",
          S3AEncryptionMethods.SSE_S3,
          delegatedFS.getServerSideEncryptionAlgorithm());
      verifyRestrictedPermissions(delegatedFS);

      executeDelegatedFSOperations(delegatedFS, testPath);
      delegatedFS.mkdirs(testPath);

      IDBTestUtils.MetricDiff issueDiff = new IDBTestUtils.MetricDiff(
          delegatedFS,
          Statistic.DELEGATION_TOKENS_ISSUED);

      // verify that the FS returns the existing token when asked
      // so that chained deployments will work
      AbstractS3ATokenIdentifier tokenFromDelegatedFS
          = requireNonNull(
          delegatedFS.getDelegationToken(""),
          () -> "New token from " + delegatedFS)
          .decodeIdentifier();
      assertEquals("Newly issued token != old one",
          origTokenId,
          tokenFromDelegatedFS);
      issueDiff.assertDiffEquals("DTs issued in " + delegatedFS,
          0);
    }


    // create a second instance, which will pick up the same value
    try (S3AFileSystem secondDelegate = newS3AInstance(uri, conf)) {
      assertBoundToDT(secondDelegate, tokenKind);
      assertEquals("Encryption propagation failed",
          S3AEncryptionMethods.SSE_S3,
          secondDelegate.getServerSideEncryptionAlgorithm());
      ContractTestUtils.assertDeleted(secondDelegate, testPath, true);
      assertNotNull("unbounded DT", secondDelegate.getDelegationToken(""));
    }
  }

  /**
   * Override/extension point: run operations within a delegated FS.
   * @param delegatedFS filesystem.
   * @param testPath path to work on.
   * @throws IOException failures
   */
  protected void executeDelegatedFSOperations(final S3AFileSystem delegatedFS,
      final Path testPath) throws Exception {
    ContractTestUtils.assertIsDirectory(delegatedFS, new Path("/"));
    ContractTestUtils.touch(delegatedFS, testPath);
    ContractTestUtils.assertDeleted(delegatedFS, testPath, false);
    delegatedFS.mkdirs(testPath);
    ContractTestUtils.assertIsDirectory(delegatedFS, testPath);
    Path srcFile = new Path(testPath, "src.txt");
    Path destFile = new Path(testPath, "dest.txt");
    ContractTestUtils.touch(delegatedFS, srcFile);
    ContractTestUtils.rename(delegatedFS, srcFile, destFile);
    // this file is deleted afterwards, so leave alone
    ContractTestUtils.assertIsFile(delegatedFS, destFile);
    ContractTestUtils.assertDeleted(delegatedFS, testPath, true);
  }

  /**
   * Session tokens can read the landsat bucket without problems.
   * @param delegatedFS delegated FS
   * @throws Exception failure
   */
  protected void verifyRestrictedPermissions(final S3AFileSystem delegatedFS)
      throws Exception {

  }

  /**
   * YARN job submission uses
   * {@link TokenCache#obtainTokensForNamenodes(Credentials, Path[], Configuration)}
   * for token retrieval: call it here to verify it works.
   */
  @Test
  public void testYarnCredentialPickup() throws Throwable {
    describe("Verify tokens are picked up by the YARN"
        + " TokenCache.obtainTokensForNamenodes() API Call");
    Credentials cred = new Credentials();
    Path yarnPath = path("testYarnCredentialPickup");
    Path[] paths = new Path[]{yarnPath};
    Configuration conf = getConfiguration();
    S3AFileSystem fs = getFileSystem();
    TokenCache.obtainTokensForNamenodes(cred, paths, conf);
    assertNotNull("No Token in credentials file",
        lookupToken(
            cred,
            fs.getUri(),
            getTokenKind()));
  }

  /**
   * Test the {@code hdfs fetchdt} command works with S3A tokens.
   */
  @Test
  public void testHDFSFetchDTCommand() throws Throwable {
    describe("Use the HDFS fetchdt CLI to fetch a token");

    ExitUtil.disableSystemExit();
    S3AFileSystem fs = getFileSystem();
    Configuration conf = fs.getConf();

    URI fsUri = fs.getUri();
    String fsurl = fsUri.toString();
    File tokenfile = File.createTempFile("tokens", ".bin",
        cluster.getWorkDir());
    tokenfile.delete();

    // this will create (& leak) a new FS instance as caching is disabled.
    // but as teardown destroys all filesystems for this user, it
    // gets cleaned up at the end of the test
    String tokenFilePath = tokenfile.getAbsolutePath();

    // create the tokens as Bob.
    doAs(bobUser,
        () -> DelegationTokenFetcher.main(conf,
            args("--webservice", fsurl, tokenFilePath)));
    assertTrue("token file was not created: " + tokenfile,
        tokenfile.exists());

    // print to stdout
    String s = DelegationTokenFetcher.printTokensToString(conf,
        new Path(tokenfile.toURI()),
        false);
    LOG.info("Tokens: {}", s);
    DelegationTokenFetcher.main(conf,
        args("--print", tokenFilePath));
    DelegationTokenFetcher.main(conf,
        args("--print", "--verbose", tokenFilePath));

    // read in and retrieve token
    Credentials creds = Credentials.readTokenStorageFile(tokenfile, conf);
    AbstractS3ATokenIdentifier identifier = requireNonNull(
        lookupToken(
            creds,
            fsUri,
            getTokenKind()),
        "Token lookup");
    assertEquals("encryption secrets",
        fs.getEncryptionSecrets(),
        identifier.getEncryptionSecrets());
    assertEquals("Username of decoded token",
        bobUser.getUserName(), identifier.getUser().getUserName());

    // renew
    DelegationTokenFetcher.main(conf, args("--renew", tokenFilePath));

    // cancel
    DelegationTokenFetcher.main(conf, args("--cancel", tokenFilePath));
  }

  /**
   * Convert a vargs list to an array.
   * @param args vararg list of arguments
   * @return the generated array.
   */
  private String[] args(String... args) {
    return args;
  }

  /**
   * This test looks at the identity which goes with a DT.
   * It assumes that the username of a token == the user who created it.
   * Some tokens may change that in future (maybe use Role ARN?).
   */
  @Test
  public void testFileSystemBoundToCreator() throws Throwable {
    describe("Run tests to verify the DT Setup is bound to the creator");

    // quick sanity check to make sure alice and bob are different
    assertNotEquals("Alice and bob logins",
        aliceUser.getUserName(), bobUser.getUserName());


    final S3AFileSystem fs = getFileSystem();
    assertEquals("FS username in doAs()",
        ALICE,
        doAs(bobUser, () -> fs.getUsername()));

    UserGroupInformation fsOwner = doAs(bobUser,
        () -> fs.getDelegationTokens().get().getOwner());
    assertEquals("username mismatch",
        aliceUser.getUserName(), fsOwner.getUserName());

    Token<AbstractS3ATokenIdentifier> dt = fs.getDelegationToken(ALICE);
    AbstractS3ATokenIdentifier identifier
        = dt.decodeIdentifier();
    UserGroupInformation user = requireNonNull(identifier.getUser(),
        "null user in " + identifier);
    assertEquals("User in DT",
        aliceUser.getUserName(), user.getUserName());
  }

}
