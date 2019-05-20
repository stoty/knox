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

import static org.apache.knox.gateway.cloud.idbroker.IDBProperty.PROPERTY_SUFFIX_CREDENTIALS_TYPE;
import static org.apache.knox.gateway.cloud.idbroker.IDBProperty.PROPERTY_SUFFIX_DT_PATH;
import static org.apache.knox.gateway.cloud.idbroker.IDBProperty.PROPERTY_SUFFIX_GATEWAY;
import static org.apache.knox.gateway.cloud.idbroker.IDBProperty.PROPERTY_SUFFIX_ONLY_GROUPS_METHOD;
import static org.apache.knox.gateway.cloud.idbroker.IDBProperty.PROPERTY_SUFFIX_ONLY_USER_METHOD;
import static org.apache.knox.gateway.cloud.idbroker.IDBProperty.PROPERTY_SUFFIX_PASSWORD;
import static org.apache.knox.gateway.cloud.idbroker.IDBProperty.PROPERTY_SUFFIX_PATH;
import static org.apache.knox.gateway.cloud.idbroker.IDBProperty.PROPERTY_SUFFIX_SPECIFIC_GROUP_METHOD;
import static org.apache.knox.gateway.cloud.idbroker.IDBProperty.PROPERTY_SUFFIX_SPECIFIC_ROLE_METHOD;
import static org.apache.knox.gateway.cloud.idbroker.IDBProperty.PROPERTY_SUFFIX_TRUSTSTORE_LOCATION;
import static org.apache.knox.gateway.cloud.idbroker.IDBProperty.PROPERTY_SUFFIX_TRUSTSTORE_PASS;
import static org.apache.knox.gateway.cloud.idbroker.IDBProperty.PROPERTY_SUFFIX_TRUSTSTORE_PASSWORD;
import static org.apache.knox.gateway.cloud.idbroker.IDBProperty.PROPERTY_SUFFIX_USERNAME;
import static org.apache.knox.gateway.cloud.idbroker.IDBProperty.PROPERTY_SUFFIX_USE_DT_CERT;
import static org.apache.knox.gateway.cloud.idbroker.abfs.AbfsIDBProperty.IDBROKER_CREDENTIALS_TYPE;
import static org.apache.knox.gateway.cloud.idbroker.abfs.AbfsIDBProperty.IDBROKER_DT_PATH;
import static org.apache.knox.gateway.cloud.idbroker.abfs.AbfsIDBProperty.IDBROKER_GATEWAY;
import static org.apache.knox.gateway.cloud.idbroker.abfs.AbfsIDBProperty.IDBROKER_ONLY_GROUPS_METHOD;
import static org.apache.knox.gateway.cloud.idbroker.abfs.AbfsIDBProperty.IDBROKER_ONLY_USER_METHOD;
import static org.apache.knox.gateway.cloud.idbroker.abfs.AbfsIDBProperty.IDBROKER_PASSWORD;
import static org.apache.knox.gateway.cloud.idbroker.abfs.AbfsIDBProperty.IDBROKER_PATH;
import static org.apache.knox.gateway.cloud.idbroker.abfs.AbfsIDBProperty.IDBROKER_SPECIFIC_GROUP_METHOD;
import static org.apache.knox.gateway.cloud.idbroker.abfs.AbfsIDBProperty.IDBROKER_SPECIFIC_ROLE_METHOD;
import static org.apache.knox.gateway.cloud.idbroker.abfs.AbfsIDBProperty.IDBROKER_TRUSTSTORE_LOCATION;
import static org.apache.knox.gateway.cloud.idbroker.abfs.AbfsIDBProperty.IDBROKER_TRUSTSTORE_PASS;
import static org.apache.knox.gateway.cloud.idbroker.abfs.AbfsIDBProperty.IDBROKER_TRUSTSTORE_PASSWORD;
import static org.apache.knox.gateway.cloud.idbroker.abfs.AbfsIDBProperty.IDBROKER_USERNAME;
import static org.apache.knox.gateway.cloud.idbroker.abfs.AbfsIDBProperty.IDBROKER_USE_DT_CERT;
import static org.easymock.EasyMock.expect;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import com.amazonaws.util.StringInputStream;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.fs.azurebfs.oauth2.AzureADToken;
import org.apache.hadoop.security.UserGroupInformation;
import org.apache.knox.gateway.cloud.idbroker.AbstractIDBClient;
import org.apache.knox.gateway.cloud.idbroker.AbstractIDBClientTest;
import org.apache.knox.gateway.cloud.idbroker.IDBProperty;
import org.apache.knox.gateway.shell.BasicResponse;
import org.apache.knox.test.category.UnitTests;
import org.easymock.IMockBuilder;
import org.junit.Test;
import org.junit.experimental.categories.Category;

import java.io.IOException;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

@Category(UnitTests.class)
public class AbfsIDBClientTest extends AbstractIDBClientTest {
  private static final Map<String, IDBProperty> PROPERTY_MAP;

  static {
    Map<String, IDBProperty> map = new HashMap<>();

    map.put(PROPERTY_SUFFIX_GATEWAY, IDBROKER_GATEWAY);
    map.put(PROPERTY_SUFFIX_USERNAME, IDBROKER_USERNAME);
    map.put(PROPERTY_SUFFIX_PASSWORD, IDBROKER_PASSWORD);
    map.put(PROPERTY_SUFFIX_TRUSTSTORE_LOCATION, IDBROKER_TRUSTSTORE_LOCATION);
    map.put(PROPERTY_SUFFIX_TRUSTSTORE_PASSWORD, IDBROKER_TRUSTSTORE_PASSWORD);
    map.put(PROPERTY_SUFFIX_TRUSTSTORE_PASS, IDBROKER_TRUSTSTORE_PASS);
    map.put(PROPERTY_SUFFIX_SPECIFIC_GROUP_METHOD, IDBROKER_SPECIFIC_GROUP_METHOD);
    map.put(PROPERTY_SUFFIX_SPECIFIC_ROLE_METHOD, IDBROKER_SPECIFIC_ROLE_METHOD);
    map.put(PROPERTY_SUFFIX_ONLY_GROUPS_METHOD, IDBROKER_ONLY_GROUPS_METHOD);
    map.put(PROPERTY_SUFFIX_ONLY_USER_METHOD, IDBROKER_ONLY_USER_METHOD);
    map.put(PROPERTY_SUFFIX_PATH, IDBROKER_PATH);
    map.put(PROPERTY_SUFFIX_DT_PATH, IDBROKER_DT_PATH);
    map.put(PROPERTY_SUFFIX_CREDENTIALS_TYPE, IDBROKER_CREDENTIALS_TYPE);
    map.put(PROPERTY_SUFFIX_USE_DT_CERT, IDBROKER_USE_DT_CERT);

    PROPERTY_MAP = Collections.unmodifiableMap(map);
  }

  @Test
  public void testExtractCloudCredentialsFromResponse() throws IOException {
    UserGroupInformation owner = createMock(UserGroupInformation.class);

    String json =
        "{" +
            "  \"access_token\": \"eyJ0eXAiOiJKV1...Q\"," +
            "  \"expires_on\": \"1556247141\"" +
            "}";

    BasicResponse basicResponse = createMock(BasicResponse.class);
    expect(basicResponse.getStatusCode()).andReturn(200).once();
    expect(basicResponse.getContentType()).andReturn("application/json").once();
    expect(basicResponse.getContentLength()).andReturn((long) json.length()).once();
    expect(basicResponse.getStream()).andReturn(new StringInputStream(json)).once();

    AbfsIDBClient client = new AbfsIDBClient(new Configuration(), owner);

    replayAll();

    AzureADToken credentials = client.extractCloudCredentialsFromResponse(basicResponse);
    assertNotNull(credentials);
    assertEquals("eyJ0eXAiOiJKV1...Q", credentials.getAccessToken());
    assertEquals(1556247141000L, credentials.getExpiry().getTime());

    verifyAll();
  }

  @Override
  protected IMockBuilder<? extends AbstractIDBClient> getIDBClientMockBuilder(Configuration configuration, UserGroupInformation owner) throws IOException {
    return createMockBuilder(AbfsIDBClient.class)
        .withConstructor(configuration, owner);
  }

  @Override
  protected Map<String, IDBProperty> getPropertyMap() {
    return PROPERTY_MAP;
  }
}