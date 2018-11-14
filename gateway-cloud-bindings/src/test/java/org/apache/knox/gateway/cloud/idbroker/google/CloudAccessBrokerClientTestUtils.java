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
import org.apache.knox.gateway.shell.KnoxSession;
import org.apache.knox.gateway.shell.knox.token.Get;
import org.apache.knox.gateway.shell.knox.token.Token;

import java.io.File;

class CloudAccessBrokerClientTestUtils {

  static final String DEFAULT_CAB_ADDRESS = "https://localhost:8443/gateway";
  static final String DEFAULT_DT_PATH     = "dt";
  static final String DEFAULT_CAB_PATH    = "gcp-cab";

  static final String DELEGATION_TOKEN_BINDING = CABDelegationTokenBinding.class.getName();

  static final String TRUST_STORE_LOCATION =
                              System.getenv(CloudAccessBrokerBindingConstants.CONFIG_CAB_TRUST_STORE_LOCATION_ENV_VAR);

  static final String TRUST_STORE_PASS =
                              System.getenv(CloudAccessBrokerBindingConstants.CONFIG_CAB_TRUST_STORE_PASS_ENV_VAR);

  static final String DT_AUTH_USERNAME;
  static {
    String authUser = System.getenv("CLOUD_ACCESS_BROKER_USERNAME");
    DT_AUTH_USERNAME = authUser != null ? authUser : "admin";
  }

  static final String DT_AUTH_PASS;
  static {
    String authUser = System.getenv(CloudAccessBrokerBindingConstants.DT_PASS_ENV_VAR);
    DT_AUTH_PASS = authUser != null ? authUser : DT_AUTH_USERNAME + "-password";
  }

  static final String CLOUD_ACCESS_BROKER_ADDRESS;
  static {
    String address = System.getenv(CloudAccessBrokerBindingConstants.CONFIG_CAB_ADDRESS.replace(".", "_"));
    CLOUD_ACCESS_BROKER_ADDRESS = address != null ? address : DEFAULT_CAB_ADDRESS;
  }

  static final String CAB_PATH;
  static {
    String path = System.getenv(CloudAccessBrokerBindingConstants.CONFIG_CAB_PATH.replace(".", "_"));
    CAB_PATH = path != null ? path : DEFAULT_CAB_PATH;
  }

  static final String DT_PATH;
  static {
    String path = System.getenv(CloudAccessBrokerBindingConstants.CONFIG_CAB_DT_PATH.replace(".", "_"));
    DT_PATH = path != null ? path : DEFAULT_DT_PATH;
  }

  static final String CREDENTIAL_PROVIDER_PATH = System.getenv("HADOOP_SECURITY_CREDENTIAL_PROVIDER_PATH");;

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
    KnoxSession session = KnoxSession.login(CLOUD_ACCESS_BROKER_ADDRESS + "/" + DT_PATH,
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

}
