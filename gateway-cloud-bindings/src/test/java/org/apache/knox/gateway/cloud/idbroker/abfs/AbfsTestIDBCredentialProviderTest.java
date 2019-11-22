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

package org.apache.knox.gateway.cloud.idbroker.abfs;

import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.test.LambdaTestUtils;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

import java.io.IOException;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.time.Instant;
import java.util.Date;

import static org.apache.knox.gateway.cloud.idbroker.IDBConstants.LOCAL_GATEWAY;
import static org.apache.knox.gateway.cloud.idbroker.abfs.AbfsIDBProperty.IDBROKER_TEST_TOKEN_PATH;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

public class AbfsTestIDBCredentialProviderTest {
  @Rule
  public final TemporaryFolder testFolder = new TemporaryFolder();

  @Test
  public void testPathNotSpecified() throws Exception {
    Configuration configuration = new Configuration();

    assertNull(configuration.get(IDBROKER_TEST_TOKEN_PATH.getPropertyName()));

    AbfsTestIDBCredentialProvider provider = new AbfsTestIDBCredentialProvider();
    provider.bind(new URI(LOCAL_GATEWAY), configuration);

    // This should fail since a real token will try to be acquired but the facility is not set up to do so.
    LambdaTestUtils.intercept(IOException.class, provider::getAccessToken);
  }

  @Test
  public void testPathDoesNotExist() throws Exception {
    String invalidPath = testFolder.getRoot().getAbsolutePath() + "/non_existent_file";

    Configuration configuration = new Configuration();
    configuration.set(IDBROKER_TEST_TOKEN_PATH.getPropertyName(), invalidPath);

    assertEquals(invalidPath, configuration.get(IDBROKER_TEST_TOKEN_PATH.getPropertyName()));
    assertFalse(Files.exists(Paths.get(invalidPath)));

    AbfsTestIDBCredentialProvider provider = new AbfsTestIDBCredentialProvider();
    provider.bind(new URI(LOCAL_GATEWAY), configuration);

    // This should fail since a real token will try to be acquired but the facility is not set up to do so.
    LambdaTestUtils.intercept(IOException.class, provider::getAccessToken);
  }

  @Test
  public void testPathIsNotAFile() throws Exception {
    String directoryPath = testFolder.newFolder().getAbsolutePath();

    Configuration configuration = new Configuration();
    configuration.set(IDBROKER_TEST_TOKEN_PATH.getPropertyName(), directoryPath);

    assertEquals(directoryPath, configuration.get(IDBROKER_TEST_TOKEN_PATH.getPropertyName()));
    assertTrue(Files.isDirectory(Paths.get(directoryPath)));

    AbfsTestIDBCredentialProvider provider = new AbfsTestIDBCredentialProvider();
    provider.bind(new URI(LOCAL_GATEWAY), configuration);

    // This should fail since a real token will try to be acquired but the facility is not set up to do so.
    LambdaTestUtils.intercept(IOException.class, provider::getAccessToken);
  }

  @Test
  public void testGetExpiredToken() throws Exception {
    String path = getClass().getResource("/expired_access_tokens/azure.json").getPath();

    Configuration configuration = new Configuration();
    configuration.set(IDBROKER_TEST_TOKEN_PATH.getPropertyName(), path);

    assertEquals(path, configuration.get(IDBROKER_TEST_TOKEN_PATH.getPropertyName()));

    AbfsTestIDBCredentialProvider provider = new AbfsTestIDBCredentialProvider();
    provider.bind(new URI(LOCAL_GATEWAY), configuration);

    String accessToken = provider.getAccessToken();
    assertEquals("eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6IkhCeGw5bUFlNmd4YXZDa2NvT1UyVEhzRE5hMCIsImtpZCI6IkhCeGw5bUFlNmd4YXZDa2NvT1UyVEhzRE5hMCJ9.eyJhdWQiOiJodHRwczovL3N0b3JhZ2UuYXp1cmUuY29tLyIsImlzcyI6Imh0dHBzOi8vc3RzLndpbmRvd3MubmV0Lzk1MzhjOGZiLWRhNzUtNDFkOC05YjkzLTE3OTBlMGJhZDU4NS8iLCJpYXQiOjE1NTg1NTExMTYsIm5iZiI6MTU1ODU1MTExNiwiZXhwIjoxNTU4NTU1MDE2LCJhaW8iOiI0MlpnWVBnNDhWMW1nN1BUckhWYzRSc2JOOHhzQlFBPSIsImFwcGlkIjoiMTIzZDVhOWItNjI4Yy00YzRhLThiMTQtMjFmOGViNDgwNDM5IiwiYXBwaWRhY3IiOiIxIiwiaWRwIjoiaHR0cHM6Ly9zdHMud2luZG93cy5uZXQvOTUzOGM4ZmItZGE3NS00MWQ4LTliOTMtMTc5MGUwYmFkNTg1LyIsIm9pZCI6ImFmODUwOTFlLTAzMGQtNDVlOC05ODQ5LWI4MmY1ODE1MWQ5ZCIsInN1YiI6ImFmODUwOTFlLTAzMGQtNDVlOC05ODQ5LWI4MmY1ODE1MWQ5ZCIsInRpZCI6Ijk1MzhjOGZiLWRhNzUtNDFkOC05YjkzLTE3OTBlMGJhZDU4NSIsInV0aSI6IlJ5Tk9xb18wNVV1bU90c05LTDBTQUEiLCJ2ZXIiOiIxLjAifQ.y7t6O8qYPoDbn_7_3xj_DSzVXtb5uG8ZoaU2zJIZhhZmbYsXquUVKz6Z_Tjjj3nPWjObnG7E6yam1QwEQi4b453W3EjSB3fOoIGczAbq_41FS78Z4p_joD3nsPwXJ1X21FZ65YWAD4u4vQpKFVnh_n5i8wdMfQEL-Eg-mf2rbiYYdzZ6dPpseT_I25jmvtUQsMnPNLbxuD3CwrbNJAfjIAJ-DdWxHLPVN58Hz6OQnOHS4du68jmxhjEMdgoc5lnZ-P1HeUrBtoGRSPN-zj69blu3D-KEd_xlPulxtDweL8u5_kuo9Rxi1ja_LxQue1d2zRoCyT4-TTzC1enL8KdSGg",
        accessToken);

    Date expiry = provider.getExpiryTime();
    assertEquals(Instant.ofEpochSecond(1558555016L), expiry.toInstant());

    // This should fail since a real token will try to be acquired but the facility is not set up to do so.
    LambdaTestUtils.intercept(IOException.class, provider::getAccessToken);
  }
}