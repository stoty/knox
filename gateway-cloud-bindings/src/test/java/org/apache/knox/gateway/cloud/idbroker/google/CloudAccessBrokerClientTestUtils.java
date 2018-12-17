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

import org.apache.commons.io.FileUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.hadoop.conf.Configuration;
import org.apache.knox.gateway.shell.KnoxSession;
import org.apache.knox.gateway.shell.knox.token.Get;
import org.apache.knox.gateway.shell.knox.token.Token;

import java.io.File;
import java.io.FileNotFoundException;

import org.junit.AssumptionViolatedException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static org.apache.knox.gateway.cloud.idbroker.google.CABDelegationTokenBinding.E_MISSING_DT_USERNAME_CONFIG;
import static org.apache.knox.gateway.cloud.idbroker.google.CABUtils.constructURL;
import static org.apache.knox.gateway.cloud.idbroker.google.CABUtils.getConfigSecret;
import static org.apache.knox.gateway.cloud.idbroker.google.CABUtils.getRequiredConfigSecret;
import static org.apache.knox.gateway.cloud.idbroker.google.CloudAccessBrokerBindingConstants.*;
import static org.junit.Assume.assumeTrue;

final class CloudAccessBrokerClientTestUtils {

  private static final Logger LOG =
      LoggerFactory.getLogger(CloudAccessBrokerClientTestUtils.class);
  
  static final String DEFAULT_CAB_ADDRESS = "https://localhost:8443/gateway";
  static final String DEFAULT_DT_PATH     = "dt";
  static final String DEFAULT_CAB_PATH    = "gcp-cab";

  static final String DELEGATION_TOKEN_BINDING = CABDelegationTokenBinding.class.getName();

  static final String TRUST_STORE_LOCATION;

  static final String TRUST_STORE_PASS;

  static final String DT_AUTH_USERNAME;

  static final String TEST_PROJECT_ENV_VAR = "CAB_INTEGRATION_TEST_GCP_PROJECT";
  static final String CONFIG_TEST_PROJECT = "test.gcp.project";
  
  static final String CONFIG_TEST_GS_FILESSYSTEM_KEY = "test.gs.filesystem";

  static final String TEST_BUCKET_ENV_VAR  = "CAB_INTEGRATION_TEST_GCP_BUCKET";

  static final String DT_AUTH_PASS;

  /**
   * Evaluated address of gateway
   */
  static final String CLOUD_ACCESS_BROKER_ADDRESS;

  static final String CAB_PATH;

  static final String DT_PATH;

  private static final Configuration conf = new Configuration();


  static final String CREDENTIAL_PROVIDER_PATH;

  private CloudAccessBrokerClientTestUtils() {
  }

  /**
   * Get a test option from, in order:
   * <ol>
   *   <li>key in the default configuration (i.e. auth-keys.xml)</li>
   *   <li>same key, with . replaced by _ as an env variable name</li>
   *   <li>the default value</li>
   * </ol>
   * @param key key
   * @param defval default value
   * @return evaluated answer
   */
  private static String testOption(String key, String defval) {
    return testOption(key, key.replace(".", "_"), defval);
  }

  /**
   * Get a test option from, in order:
   * <ol>
   *   <li>key in the default configuration (i.e. auth-keys.xml)</li>
   *   <li>env variable "envkey"</li>
   *   <li>the default value</li>
   * </ol>
   * @param key key
   * @param envkey environment variable name
   * @param defval default value
   * @return evaluated answer
   */
  private static String testOption(String key, String envkey, String defval) {
    String env = System.getenv(envkey);
    return conf.get(key, env != null ? env : defval);
  }

  static {
    TRUST_STORE_LOCATION = CABUtils.getTrustStoreLocation(conf); 
    TRUST_STORE_PASS = CABUtils.getTrustStorePass(conf);

    String dtAuthUsername = null;
    try {
      dtAuthUsername = getRequiredConfigSecret(conf,
          CONFIG_DT_USERNAME,
          DT_USERNAME_ENV_VAR,
          E_MISSING_DT_USERNAME_CONFIG);
    } catch (Exception e) {
      LOG.warn(e.getMessage());
    }
    DT_AUTH_USERNAME = dtAuthUsername;

    String dtAuthPass = null;
    if (StringUtils.isNotEmpty(DT_AUTH_USERNAME)) {
      try {
        String dtPass = getConfigSecret(conf,
            CONFIG_DT_PASS,
            DT_PASS_ENV_VAR);
        dtAuthPass = dtPass != null ? dtPass : (DT_AUTH_USERNAME + "-password");
      } catch (Exception e) {
        LOG.warn(e.getMessage());
      }
    }
    DT_AUTH_PASS = dtAuthPass;
    CLOUD_ACCESS_BROKER_ADDRESS = testOption(CONFIG_CAB_ADDRESS, "");
    CAB_PATH = testOption(CONFIG_CAB_PATH, DEFAULT_CAB_PATH);
    DT_PATH = testOption(CONFIG_CAB_DT_PATH,  DEFAULT_DT_PATH);
    String path = System.getenv(
        "HADOOP_SECURITY_CREDENTIAL_PROVIDER_PATH");
    if (path == null) {
      path = "";
    }
    CREDENTIAL_PROVIDER_PATH = path;
  }


  private static final File tokenCacheFile       = new File(System.getProperty("user.home"), ".knoxtokencache");
  private static final File tokenCacheBackupFile = new File(System.getProperty("user.home"), ".knoxtokencache.save");


  static void backupTokenCache() throws Exception {
    // Back-up the token cache file if it exists
    if (tokenCacheFile.exists()) {
      FileUtils.copyFile(tokenCacheFile, tokenCacheBackupFile);
    }
  }


  static void restoreTokenCacheBackup() throws Exception {
    if (tokenCacheBackupFile.exists()) {
      FileUtils.copyFile(tokenCacheBackupFile, tokenCacheFile);
      FileUtils.forceDelete(tokenCacheBackupFile);
    }
  }

  static void deleteTokenCache() throws Exception {
    if (tokenCacheFile.exists()) {
      FileUtils.forceDelete(tokenCacheFile);
    }
  }

  /**
   * Simulate the knox init command-line by getting a Knox token, and persisting it to the well-known knox token cache
   * file location, such that subsequent uses of the KnoxTokenCredentialCollector will find it.
   *
   * If there is an existing knox token cache file, it will be backed-up by this method.
   *
   * @throws Exception
   */
  static void knoxInit() throws Exception {
    knoxInit(DT_AUTH_USERNAME, DT_AUTH_PASS, null, null);
  }


  /**
   * Simulate the knox init command-line by getting a Knox token, and persisting it to the well-known knox token cache
   * file location, such that subsequent uses of the KnoxTokenCredentialCollector will find it.
   *
   * If there is an existing knox token cache file, it will be backed-up by this method.
   *
   * @param truststoreLocation The location of the trust store this client should employ.
   * @param truststorePass     The password associated with the specified trust store.
   *
   * @throws Exception
   */
  static void knoxInit(String truststoreLocation, String truststorePass) throws Exception {
    knoxInit(DT_AUTH_USERNAME, DT_AUTH_PASS, truststoreLocation, truststorePass);
  }


  /**
   * Simulate the knox init command-line by getting a Knox token, and persisting it to the well-known knox token cache
   * file location, such that subsequent uses of the KnoxTokenCredentialCollector will find it.
   *
   * If there is an existing knox token cache file, it will be backed-up by this method.
   *
   * @param username           The username for authenticating to get the knox token.
   * @param pwd                The password for authenticating to get the knox token.
   * @param truststoreLocation The location of the trust store this client should employ.
   * @param truststorePass     The password associated with the specified trust store.
   *
   *
   * @throws Exception
   */
  static void knoxInit(final String username,
                       final String pwd,
                       final String truststoreLocation,
                       final String truststorePass) throws Exception {
    if (truststoreLocation != null) {
      File store = new File(truststoreLocation);
      if (!store.exists()) {
        throw new FileNotFoundException("trust store " + store);
      }
    }
    String addr = constructURL(CLOUD_ACCESS_BROKER_ADDRESS, DT_PATH);
    LOG.info("Connecting to {} as {}", addr, username);
    KnoxSession session = KnoxSession.login(addr,
                                            username,
                                            pwd,
                                            truststoreLocation,
                                            truststorePass);
    Get.Response resp = Token.get(session).now();

    // Back-up the token cache file if it exists
    backupTokenCache();

    try {
      FileUtils.write(tokenCacheFile, resp.getString());
    } catch (Throwable t){
      restoreTokenCacheBackup();
    }
  }

  /**
   * Get the required test bucket.
   * @param conf config to work with.
   * @return the bucket always with the gs:// prefix
   * @throws AssumptionViolatedException if there was no one
   */
  static String requireTestBucket(Configuration conf) 
      throws AssumptionViolatedException {
    String myTestBucket = testOption(CONFIG_TEST_GS_FILESSYSTEM_KEY, 
                                     TEST_BUCKET_ENV_VAR,
                                     null);
    assumeTrue("Test bucket must be configured via environment variable: " +
               TEST_BUCKET_ENV_VAR  + " or configuration option " +
               CONFIG_TEST_GS_FILESSYSTEM_KEY,
               myTestBucket != null);
    if (!myTestBucket.startsWith("gs://")) {
      myTestBucket = "gs://" + myTestBucket;
    }
    return myTestBucket;
  }

  /**
   * Get the required test project.
   * @param conf config to work with.
   * @return the project
   * @throws AssumptionViolatedException if there was no one
   */
  static String requireTestProject(Configuration conf) {
    final String myTestProject = testOption(CONFIG_TEST_PROJECT, 
                                            TEST_PROJECT_ENV_VAR,
                                            null);
    assumeTrue("Test project must be configured via environment variable: " +
               TEST_PROJECT_ENV_VAR + " or configuration option " +
               CONFIG_TEST_PROJECT,
               myTestProject != null);
    return myTestProject;
  }

}
