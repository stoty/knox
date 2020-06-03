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
import static org.apache.knox.gateway.cloud.idbroker.s3a.AuthResponseAWSMessageTest.ACCESS_KEY;
import static org.apache.knox.gateway.cloud.idbroker.s3a.AuthResponseAWSMessageTest.ARN;
import static org.apache.knox.gateway.cloud.idbroker.s3a.AuthResponseAWSMessageTest.EXPIRATION;
import static org.apache.knox.gateway.cloud.idbroker.s3a.AuthResponseAWSMessageTest.SECRET_ACCESS_KEY;
import static org.apache.knox.gateway.cloud.idbroker.s3a.AuthResponseAWSMessageTest.SESSION_TOKEN;
import static org.apache.knox.gateway.cloud.idbroker.s3a.AuthResponseAWSMessageTest.VALID_AWS_RESPONSE;
import static org.apache.knox.gateway.cloud.idbroker.s3a.S3AIDBProperty.IDBROKER_CREDENTIALS_TYPE;
import static org.apache.knox.gateway.cloud.idbroker.s3a.S3AIDBProperty.IDBROKER_DT_PATH;
import static org.apache.knox.gateway.cloud.idbroker.s3a.S3AIDBProperty.IDBROKER_GATEWAY;
import static org.apache.knox.gateway.cloud.idbroker.s3a.S3AIDBProperty.IDBROKER_ONLY_GROUPS_METHOD;
import static org.apache.knox.gateway.cloud.idbroker.s3a.S3AIDBProperty.IDBROKER_ONLY_USER_METHOD;
import static org.apache.knox.gateway.cloud.idbroker.s3a.S3AIDBProperty.IDBROKER_PASSWORD;
import static org.apache.knox.gateway.cloud.idbroker.s3a.S3AIDBProperty.IDBROKER_PATH;
import static org.apache.knox.gateway.cloud.idbroker.s3a.S3AIDBProperty.IDBROKER_SPECIFIC_GROUP_METHOD;
import static org.apache.knox.gateway.cloud.idbroker.s3a.S3AIDBProperty.IDBROKER_SPECIFIC_ROLE_METHOD;
import static org.apache.knox.gateway.cloud.idbroker.s3a.S3AIDBProperty.IDBROKER_TRUSTSTORE_LOCATION;
import static org.apache.knox.gateway.cloud.idbroker.s3a.S3AIDBProperty.IDBROKER_TRUSTSTORE_PASS;
import static org.apache.knox.gateway.cloud.idbroker.s3a.S3AIDBProperty.IDBROKER_TRUSTSTORE_PASSWORD;
import static org.apache.knox.gateway.cloud.idbroker.s3a.S3AIDBProperty.IDBROKER_USERNAME;
import static org.apache.knox.gateway.cloud.idbroker.s3a.S3AIDBProperty.IDBROKER_USE_DT_CERT;
import static org.easymock.EasyMock.expect;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import com.amazonaws.util.StringInputStream;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.fs.s3a.S3AFileSystem;
import org.apache.hadoop.fs.s3a.auth.MarshalledCredentials;
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
public class S3AIDBClientTest extends AbstractIDBClientTest {
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
  public void testExtractCloudCredentialsFromResponseWithFs() throws IOException {
    UserGroupInformation owner = createMock(UserGroupInformation.class);

    BasicResponse basicResponse = createMock(BasicResponse.class);
    expect(basicResponse.getStatusCode()).andReturn(200).once();
    expect(basicResponse.getContentType()).andReturn("application/json").once();
    expect(basicResponse.getContentLength()).andReturn((long) VALID_AWS_RESPONSE.length()).once();
    expect(basicResponse.getStream()).andReturn(new StringInputStream(VALID_AWS_RESPONSE)).once();

    S3AFileSystem fs = createMock(S3AFileSystem.class);
    expect(fs.getBucket()).andReturn(null);

    Configuration conf = new Configuration();
    conf.set(IDBROKER_GATEWAY.getPropertyName(), IDBROKER_GATEWAY.getDefaultValue());
    conf.set(IDBROKER_PATH.getPropertyName(), IDBROKER_PATH.getDefaultValue());

    replayAll();

    S3AIDBClient client = S3AIDBClient.createFullIDBClient(conf, owner, fs);
    MarshalledCredentials credentials = client.extractCloudCredentialsFromResponse(basicResponse);
    assertNotNull(credentials);
    assertEquals(ARN, credentials.getRoleARN());
    assertEquals(ACCESS_KEY, credentials.getAccessKey());
    assertEquals(SECRET_ACCESS_KEY, credentials.getSecretKey());
    assertEquals(SESSION_TOKEN, credentials.getSessionToken());
    assertEquals(Long.parseLong(EXPIRATION), credentials.getExpiration());

    verifyAll();
  }

  @Test
  public void testExtractCloudCredentialsFromResponseWithBucket() throws IOException {
    UserGroupInformation owner = createMock(UserGroupInformation.class);

    BasicResponse basicResponse = createMock(BasicResponse.class);
    expect(basicResponse.getStatusCode()).andReturn(200).once();
    expect(basicResponse.getContentType()).andReturn("application/json").once();
    expect(basicResponse.getContentLength()).andReturn((long) VALID_AWS_RESPONSE.length()).once();
    expect(basicResponse.getStream()).andReturn(new StringInputStream(VALID_AWS_RESPONSE)).once();

    S3AFileSystem fs = createMock(S3AFileSystem.class);
    expect(fs.getBucket()).andReturn(null);

    Configuration conf = new Configuration();
    conf.set(IDBROKER_GATEWAY.getPropertyName(), IDBROKER_GATEWAY.getDefaultValue());
    conf.set(IDBROKER_PATH.getPropertyName(), IDBROKER_PATH.getDefaultValue());

    replayAll();

    S3AIDBClient client = S3AIDBClient.createFullIDBClient(conf, owner, fs.getBucket());
    MarshalledCredentials credentials = client.extractCloudCredentialsFromResponse(basicResponse);
    assertNotNull(credentials);
    assertEquals(ARN, credentials.getRoleARN());
    assertEquals(ACCESS_KEY, credentials.getAccessKey());
    assertEquals(SECRET_ACCESS_KEY, credentials.getSecretKey());
    assertEquals(SESSION_TOKEN, credentials.getSessionToken());
    assertEquals(Long.parseLong(EXPIRATION), credentials.getExpiration());

    verifyAll();
  }

  @Override
  protected IMockBuilder<? extends AbstractIDBClient> getIDBClientMockBuilder(Configuration configuration, UserGroupInformation owner) throws IOException {
    return createMockBuilder(S3AIDBClient.class)
        .withConstructor(configuration, owner, "");
  }

  @Override
  protected Map<String, IDBProperty> getPropertyMap() {
    return PROPERTY_MAP;
  }
}