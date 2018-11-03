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

  static final String DEFAULT_CAB_ADDRESS = "https://localhost:8443/gateway/gcp-cab";
  static final String DEFAULT_DT_ADDRESS  = "https://localhost:8443/gateway/dt";

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
    String address = System.getenv(CloudAccessBrokerBindingConstants.CONFIG_CAB_ADDRESS);
    CLOUD_ACCESS_BROKER_ADDRESS = address != null ? address : DEFAULT_CAB_ADDRESS;
  }

  static final String DT_ADDRESS;
  static {
    String address = System.getenv(CloudAccessBrokerBindingConstants.CONFIG_DT_ADDRESS);
    DT_ADDRESS = address != null ? address : DEFAULT_DT_ADDRESS;
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
    knoxInit(DT_AUTH_USERNAME, DT_AUTH_PASS);
  }


  /**
   * Simulate the knox init command-line by getting a Knox token, and persisting it to the well-known knox token cache
   * file location, such that subsequent uses of the KnoxTokenCredentialCollector will find it.
   *
   * If there is an existing knox token cache file, it will be backed-up by this method.
   *
   * @param username The username for authenticating to get the knox token.
   * @param pwd      The password for authenticating to get the knox token.
   *
   * @throws Exception
   */
  static void knoxInit(final String username, final String pwd) throws Exception {
    KnoxSession session = KnoxSession.login(DT_ADDRESS, username, pwd);
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
