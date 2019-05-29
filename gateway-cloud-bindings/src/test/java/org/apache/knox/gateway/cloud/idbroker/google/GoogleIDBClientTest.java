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

import com.google.cloud.hadoop.util.AccessTokenProvider;
import org.apache.hadoop.conf.Configuration;
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
import static org.apache.knox.gateway.cloud.idbroker.google.GoogleIDBProperty.IDBROKER_CREDENTIALS_TYPE;
import static org.apache.knox.gateway.cloud.idbroker.google.GoogleIDBProperty.IDBROKER_DT_PATH;
import static org.apache.knox.gateway.cloud.idbroker.google.GoogleIDBProperty.IDBROKER_GATEWAY;
import static org.apache.knox.gateway.cloud.idbroker.google.GoogleIDBProperty.IDBROKER_ONLY_GROUPS_METHOD;
import static org.apache.knox.gateway.cloud.idbroker.google.GoogleIDBProperty.IDBROKER_ONLY_USER_METHOD;
import static org.apache.knox.gateway.cloud.idbroker.google.GoogleIDBProperty.IDBROKER_PASSWORD;
import static org.apache.knox.gateway.cloud.idbroker.google.GoogleIDBProperty.IDBROKER_PATH;
import static org.apache.knox.gateway.cloud.idbroker.google.GoogleIDBProperty.IDBROKER_SPECIFIC_GROUP_METHOD;
import static org.apache.knox.gateway.cloud.idbroker.google.GoogleIDBProperty.IDBROKER_SPECIFIC_ROLE_METHOD;
import static org.apache.knox.gateway.cloud.idbroker.google.GoogleIDBProperty.IDBROKER_TRUSTSTORE_LOCATION;
import static org.apache.knox.gateway.cloud.idbroker.google.GoogleIDBProperty.IDBROKER_TRUSTSTORE_PASS;
import static org.apache.knox.gateway.cloud.idbroker.google.GoogleIDBProperty.IDBROKER_TRUSTSTORE_PASSWORD;
import static org.apache.knox.gateway.cloud.idbroker.google.GoogleIDBProperty.IDBROKER_USERNAME;
import static org.apache.knox.gateway.cloud.idbroker.google.GoogleIDBProperty.IDBROKER_USE_DT_CERT;
import static org.easymock.EasyMock.expect;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

@Category(UnitTests.class)
public class GoogleIDBClientTest extends AbstractIDBClientTest {

  private static final String TEST_TOKEN =
      "ya29.c.EvUBGQc9KXO1R6t85lfanE7YIcMJnfo1Z9sIMtXbSWt8CliV_3HvA6MRo-qRs0t466V4wXYZi82JvnNj2S0eAISERP1w" +
      "fQuO7DWdbQy9ri64P7qsFgowIRYUgm0FgGMN1717ASeC8jvhkA_837I8n1c6vbNn1NsVzg_PT4EBcG-a84JV1Oq0-qEn56fu_SS" +
      "fBi_rx6ys_RRJyz2zqDfRbIJD1wn0E6ecOfiE-8vgJlZExwo_fjjVcb5z_8FOu2AgSk--e9tkX9KkyBjVHffQl6wcuaMbFGh15S" +
      "5kVJv342bdYfsn6e0Go97COiQ2S8ZaBh-1V2wikYQ";

  private static final String TEST_EXPIRATION = "2019-05-30T14:03:57Z";

  private static final String TEST_ACCESS_TOKEN_RESPONSE =
      "{\n" +
      "  \"accessToken\": \"" + TEST_TOKEN + "\",\n" +
      "  \"expireTime\": \"" + TEST_EXPIRATION + "\"\n" +
      "}\n";

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

    BasicResponse response = createMock(BasicResponse.class);
    expect(response.getStatusCode()).andReturn(200).once();
    expect(response.getContentType()).andReturn("application/json").once();
    expect(response.getContentLength()).andReturn((long) TEST_ACCESS_TOKEN_RESPONSE.length()).once();
    expect(response.getString()).andReturn(TEST_ACCESS_TOKEN_RESPONSE).once();

    replayAll();

    Configuration conf = new Configuration();
    conf.set(IDBROKER_GATEWAY.getPropertyName(), IDBROKER_GATEWAY.getDefaultValue());
    conf.set(IDBROKER_PATH.getPropertyName(), IDBROKER_PATH.getDefaultValue());
    GoogleIDBClient client = new GoogleIDBClient(conf, owner);

    AccessTokenProvider.AccessToken credentials = client.extractCloudCredentialsFromResponse(response);
    assertNotNull(credentials);
    assertEquals(TEST_TOKEN, credentials.getToken());
    assertEquals(DateTime.parseRfc3339(TEST_EXPIRATION).getValue(), (long) credentials.getExpirationTimeMilliSeconds());

    verifyAll();
  }

  @Override
  protected IMockBuilder<? extends AbstractIDBClient> getIDBClientMockBuilder(Configuration configuration,
                                                                              UserGroupInformation owner) {
    return createMockBuilder(GoogleIDBClient.class).withConstructor(configuration, owner);
  }

  @Override
  protected Map<String, IDBProperty> getPropertyMap() {
    return PROPERTY_MAP;
  }

}
