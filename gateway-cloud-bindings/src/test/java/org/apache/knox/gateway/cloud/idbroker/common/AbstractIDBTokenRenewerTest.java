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
package org.apache.knox.gateway.cloud.idbroker.common;

import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.io.Text;
import org.apache.hadoop.security.UserGroupInformation;
import org.apache.hadoop.security.token.Token;
import org.apache.hadoop.security.token.delegation.web.DelegationTokenIdentifier;
import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.HttpStatus;
import org.apache.http.HttpVersion;
import org.apache.http.ProtocolVersion;
import org.apache.http.StatusLine;
import org.apache.http.entity.ContentType;
import org.apache.http.entity.StringEntity;
import org.apache.http.message.BasicStatusLine;
import org.apache.knox.gateway.shell.AbstractCloudAccessBrokerRequest;
import org.apache.knox.gateway.shell.BasicResponse;
import org.apache.log4j.AppenderSkeleton;
import org.apache.log4j.Level;
import org.apache.log4j.Logger;
import org.apache.log4j.spi.LoggingEvent;
import org.easymock.EasyMock;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import javax.security.auth.Subject;
import javax.security.auth.kerberos.KerberosPrincipal;
import javax.ws.rs.core.MediaType;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.Principal;
import java.security.PrivilegedAction;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.concurrent.TimeUnit;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

/**
 * Base class for IDBroker delegation token renewer implementations.
 */
public abstract class AbstractIDBTokenRenewerTest<T extends DelegationTokenIdentifier> {

  private static final String RENEWER_MISMATCH_REGEX =
                                    "The user \\(.*\\) does not match the renewer declared for the token: .*";

  private static final String MSG_RENEW_TOKEN = "Renewing ";

  private static final String MSG_CANCEL_TOKEN = "Canceling ";

  private static final String MSG_ERR_NO_RENEWER_FOR_TOKEN =
                                    "Operation not permitted. No renewer is specified in the identifier.";

  private final org.apache.log4j.Logger logger = Logger.getLogger("org.apache.knox.gateway.cloud.idbroker.common");

  private TestAppender logCapture;
  private Level        originalLevel;

  @Before
  public void setUp() {
    originalLevel = logger.getLevel();
    logger.setLevel(Level.DEBUG);
    logCapture = new TestAppender();
    logger.addAppender(logCapture);
  }

  @After
  public void tearDown() {
    logger.removeAppender(logCapture);
    logger.setLevel(originalLevel);
  }

  @Test
  public void testHandlesKind() {
    assertTrue(getTokenRenewerInstance().handleKind(getTokenKindForTest()));
  }

  @Test
  public void testIsManaged() throws Exception {
    assertTrue(getTokenRenewerInstance().isManaged(createTestToken(null)));
  }

  /**
   * ENGESC-7776
   */
  @Test
  public void testRenewalDisabled() throws Exception {
    final String declaredRenewer = "test-renewer";
    final Text allowedRenewer = new Text(declaredRenewer);

    final String responseEntity = "{\n  \"renewed\": \"true\",\n  \"expires\": \"-1\"\n}\n"; // < zero expiration result
    final HttpEntity httpEntity = new StringEntity(responseEntity, ContentType.APPLICATION_JSON);
    final HttpResponse response = EasyMock.createNiceMock(HttpResponse.class);
    EasyMock.expect(response.getEntity()).andReturn(httpEntity).anyTimes();
    EasyMock.expect(response.getStatusLine()).andReturn(new StatusLine() {
      @Override
      public ProtocolVersion getProtocolVersion() { return new ProtocolVersion("http", 1, 1); }

      @Override
      public int getStatusCode() { return 200; }

      @Override
      public String getReasonPhrase() { return "OK"; }
    }).anyTimes();
    EasyMock.replay(response);

    final Token<T> testToken = createTestToken(allowedRenewer);

    // Since the delegation token identifier has the expiration in seconds, the renewer should be converting that to
    // milliseconds when renewal requests return an expiration value < 0 because clients of the renewer are expecting
    // units of milliseconds. ENGESC-7776
    long expInMillis =
            TimeUnit.SECONDS.toMillis(getTokenRenewerInstance().getTokenExpiration(testToken.decodeIdentifier()));

    doTestRenewToken(testToken, getConfiguration(), response, expInMillis);
  }

  @Test
  public void testMatchingRenewerForRenewal() throws Exception {
    final String declaredRenewer = "test-renewer";
    try {
      doTestRenewToken(new Text(declaredRenewer));
    } catch (RuntimeException e) {
      Throwable t = e.getCause();
      assertNotNull(t);
      assertTrue(t instanceof IOException);
      assertTrue(t.getMessage().contains("Error renewing token"));
    }
    List<String> logMessages = logCapture.getMessages();
    assertRenewingLogMessage(logMessages);
    assertTrue(logMessages.get(6).contains("Error renewing token: "));
  }

  private void assertRenewingLogMessage(List<String> logMessages) {
    assertTrue(logMessages.get(1).startsWith(MSG_RENEW_TOKEN));
  }

  @Test
  public void testInvalidRenewer() throws Exception {
    final String declaredRenewer = "validRenewer";
    try {
      doTestRenewToken(new Text(declaredRenewer));
      fail("Expected an IOException because the renewer is invalid.");
    } catch (RuntimeException e) {
      Throwable t = e.getCause();
      assertNotNull(t);
      assertTrue(t instanceof IOException);
      assertTrue(t.getMessage().contains("Invalid renewer"));
    }
    List<String> logMessages = logCapture.getMessages();
    assertRenewingLogMessage(logMessages);
    assertTrue(logMessages.get(2).matches(RENEWER_MISMATCH_REGEX));
  }

  @Test
  public void testRenewalWithNullRenewerSpecifiedOnToken() throws Exception {
    try {
      doTestRenewToken(null);
      fail("Expected an IOException because the renewer is invalid.");
    } catch (RuntimeException e) {
      Throwable t = e.getCause();
      assertNotNull(t);
      assertTrue(t instanceof IOException);
      assertTrue(t.getMessage().contains("Invalid renewer"));
    }
    List<String> logMessages = logCapture.getMessages();
    assertRenewingLogMessage(logMessages);
    assertEquals(MSG_ERR_NO_RENEWER_FOR_TOKEN, logMessages.get(2));
  }

  @Test
  public void testRenewalWithEmptyRenewerSpecifiedOnToken() throws Exception {
    try {
      doTestRenewToken(new Text());
      fail("Expected an IOException because the renewer is invalid.");
    } catch (RuntimeException e) {
      Throwable t = e.getCause();
      assertNotNull(t);
      assertTrue(t instanceof IOException);
      assertTrue(t.getMessage().contains("Invalid renewer"));
    }
    List<String> logMessages = logCapture.getMessages();
    assertRenewingLogMessage(logMessages);
    assertEquals(MSG_ERR_NO_RENEWER_FOR_TOKEN, logMessages.get(2));
  }

  @Test
  public void testMatchingRenewerForCancel() throws Exception {
    final String declaredRenewer = "test-renewer";
    try {
      doTestCancelToken(new Text(declaredRenewer));
    } catch (RuntimeException e) {
      Throwable t = e.getCause();
      assertNotNull(t);
      assertTrue(t instanceof IOException);
      assertTrue(t.getMessage().contains("Error canceling token"));
    }
    List<String> logMessages = logCapture.getMessages();
    assertTrue(logMessages.get(0).startsWith(MSG_CANCEL_TOKEN));
    assertTrue(logMessages.get(6).contains("Error canceling token: "));
  }

  @Test
  public void testInvalidCancelRenewer() throws Exception {
    final String declaredRenewer = "validRenewer";
    try {
      doTestCancelToken(new Text(declaredRenewer));
      fail("Expected an IOException because the renewer is invalid.");
    } catch (RuntimeException e) {
      Throwable t = e.getCause();
      assertNotNull(t);
      assertTrue(t instanceof IOException);
      assertTrue(t.getMessage().contains("Invalid renewer"));
    }
    List<String> logMessages = logCapture.getMessages();
    assertTrue(logMessages.get(0).startsWith(MSG_CANCEL_TOKEN));
    assertTrue(logMessages.get(2).matches(RENEWER_MISMATCH_REGEX));
  }

  @Test
  public void testCancelWithNullRenewerSpecifiedOnToken() throws Exception {
    try {
      doTestCancelToken(null);
      fail("Expected an IOException because the renewer is invalid.");
    } catch (RuntimeException e) {
      Throwable t = e.getCause();
      assertNotNull(t);
      assertTrue(t instanceof IOException);
      assertTrue(t.getMessage().contains("Invalid renewer"));
    }
    List<String> logMessages = logCapture.getMessages();
    assertTrue(logMessages.get(0).startsWith(MSG_CANCEL_TOKEN));
    assertEquals(MSG_ERR_NO_RENEWER_FOR_TOKEN, logMessages.get(2));
  }

  @Test
  public void testCancelWithEmptyRenewerSpecifiedOnToken() throws Exception {
    try {
      doTestCancelToken(new Text());
      fail("Expected an IOException because the renewer is invalid.");
    } catch (RuntimeException e) {
      Throwable t = e.getCause();
      assertNotNull(t);
      assertTrue(t instanceof IOException);
      assertTrue(t.getMessage().contains("Invalid renewer"));
    }
    List<String> logMessages = logCapture.getMessages();
    assertTrue(logMessages.get(0).startsWith(MSG_CANCEL_TOKEN));
    assertEquals(MSG_ERR_NO_RENEWER_FOR_TOKEN, logMessages.get(2));
  }

  @Test
  public void testBadCancelRequestWithServerManagedStateEnabled() throws Exception {
    final String reasonPhrase = "Bad Request";
    final StatusLine statusLine = new BasicStatusLine(HttpVersion.HTTP_1_1, HttpStatus.SC_BAD_REQUEST, reasonPhrase);
    final String errorMessage = "Unknown token: junkaccesstoken";

    final StringEntity responseEntity =
            createResponseEntity("{\n  \"revoked\": \"false\",\n  \"error\": \"" + errorMessage + "\"\n}\n");

    HttpResponse response = EasyMock.createNiceMock(HttpResponse.class);
    EasyMock.expect(response.getStatusLine()).andReturn(statusLine).anyTimes();
    EasyMock.expect(response.getEntity()).andReturn(responseEntity).anyTimes();
    EasyMock.replay(response);

    final String declaredRenewer = "test-renewer";
    try {
      doTestCancelToken(new Text(declaredRenewer), response);
      fail("Expected an IOException because the token is unknown.");
    } catch (RuntimeException e) {
      Throwable t = e.getCause();
      assertNotNull(t);
      assertTrue(t instanceof IOException);
      assertTrue(t.getMessage().contains("Error canceling token"));
    }
    List<String> logMessages = logCapture.getMessages();
    assertTrue(logMessages.get(0).startsWith(MSG_CANCEL_TOKEN));
    assertTrue(logMessages.get(4).contains(errorMessage));
  }

  @Test
  public void testBadCancelRequestWithServerManagedStateEnabledButNoResponseEntity() throws Exception {
    final String reasonPhrase = "Bad Request";
    final StatusLine statusLine = new BasicStatusLine(HttpVersion.HTTP_1_1, HttpStatus.SC_BAD_REQUEST, reasonPhrase);

    HttpResponse response = EasyMock.createNiceMock(HttpResponse.class);
    EasyMock.expect(response.getStatusLine()).andReturn(statusLine).anyTimes();
    EasyMock.expect(response.getEntity()).andReturn(null).anyTimes();
    EasyMock.replay(response);

    final String declaredRenewer = "test-renewer";
    try {
      doTestCancelToken(new Text(declaredRenewer), response);
      fail("Expected an IOException because there is no response entity.");
    } catch (RuntimeException e) {
      Throwable t = e.getCause();
      assertNotNull(t);
      assertTrue(t instanceof IOException);
      assertTrue(t.getMessage().contains("Error canceling token"));
    }
    List<String> logMessages = logCapture.getMessages();
    assertTrue(logMessages.get(0).startsWith(MSG_CANCEL_TOKEN));
    assertTrue(logMessages.get(4).contains("Failed to cancel token: "));
    assertTrue(logMessages.get(4).contains(String.valueOf(HttpStatus.SC_BAD_REQUEST)));
  }

  /**
   * Token renewers should not throw an exception if they receive a HTTP 400 response because server-managed token state
   * is NOT enabled, but they should log the fact that the token has not been cancelled.
   */
  @Test
  public void testBadCancelRequest() throws Exception {
    final String reasonPhrase = "Bad Request";
    final StatusLine statusLine = new BasicStatusLine(HttpVersion.HTTP_1_1, HttpStatus.SC_BAD_REQUEST, reasonPhrase);
    final String errorMessage = "Token revocation support is not configured";

    final StringEntity responseEntity =
            createResponseEntity("{\n  \"revoked\": \"false\",\n  \"error\": \"" + errorMessage + "\"\n}\n");

    HttpResponse response = EasyMock.createNiceMock(HttpResponse.class);
    EasyMock.expect(response.getStatusLine()).andReturn(statusLine).anyTimes();
    EasyMock.expect(response.getEntity()).andReturn(responseEntity).anyTimes();
    EasyMock.replay(response);

    final String declaredRenewer = "test-renewer";
    doTestCancelToken(new Text(declaredRenewer), response);
    List<String> logMessages = logCapture.getMessages();
    assertTrue(logMessages.get(0).startsWith(MSG_CANCEL_TOKEN));
    assertTrue(logMessages.get(3).contains("Failed to cancel token: "));
    assertTrue(logMessages.get(3).contains(String.valueOf(HttpStatus.SC_BAD_REQUEST)));
    assertTrue(logMessages.get(4).contains(errorMessage)); // The response entity should have been logged
  }

  /**
   * Token renewers should support HA configuration, which includes a comma-separated list of addresses as the value
   * for the IDBroker gateway address property, for token renewal.
   */
  @Test
  public void testRenewalRequestWithHAConfig() throws Exception {
    final String reasonPhrase = "OK";
    final StatusLine statusLine = new BasicStatusLine(HttpVersion.HTTP_1_1, HttpStatus.SC_OK, reasonPhrase);
    final String expiration = String.valueOf(Instant.now().getEpochSecond());

    final StringEntity responseEntity =
            createResponseEntity("{\n  \"renewed\": \"true\",\n  \"expires\": \"" + expiration + "\"\n}\n");

    HttpResponse response = EasyMock.createNiceMock(HttpResponse.class);
    EasyMock.expect(response.getStatusLine()).andReturn(statusLine).anyTimes();
    EasyMock.expect(response.getEntity()).andReturn(responseEntity).anyTimes();
    EasyMock.replay(response);

    final String declaredRenewer = "test-renewer";
    doTestRenewToken(new Text(declaredRenewer),
                     getConfiguration("http://gateway1:8444/gateway/","http://gateway2:8444/gateway/"),
                     response,
                     Long.parseLong(expiration));
    List<String> logMessages = logCapture.getMessages();
    assertRenewingLogMessage(logMessages);
    assertTrue(logMessages.get(3).contains("Token renewed."));
    assertTrue(logMessages.get(4).startsWith("Updated token expiration: "));
  }

  /**
   * Token renewers should support failover for token renewal when HA is configured.
   */
  @Test
  public void testRenewalRequestFailover() throws Exception {
    final String declaredRenewer = "test-renewer";
    final String[] endpoints = new String[]{"http://gateway1:8444/gateway/","http://gateway2:8444/gateway/"};

    try {
      doTestRenewToken(new Text(declaredRenewer),
                       getConfiguration(endpoints),
                       null,
                       Instant.now().getEpochSecond());
    } catch (RuntimeException e) {
      Throwable cause = e.getCause();
      assertTrue(cause instanceof IOException);
      assertTrue(cause.getMessage().contains("Error renewing token"));
    }
    List<String> logMessages = logCapture.getMessages();
    assertRenewingLogMessage(logMessages);
    assertTrue(logMessages.get(8).contains("Failing over to "));
    // Determine what the next failover endpoint should be based on the current one
    int nextFailoverEndpoint = logMessages.get(8).contains(endpoints[0]) ? 1 : 0;
    assertTrue(logMessages.get(15).contains("Failing over to " + endpoints[nextFailoverEndpoint]));
    assertTrue(logMessages.get(20).startsWith("Error renewing token: "));
  }

  /**
   * Token renewers should support failover for token revocation when HA is configured.
   */
  @Test
  public void testRevocationRequestFailover() throws Exception {
    final String declaredRenewer = "test-renewer";
    final String[] endpoints = new String[]{"http://gateway1:8444/gateway/","http://gateway2:8444/gateway/"};

    try {
      doTestCancelToken(new Text(declaredRenewer), getConfiguration(endpoints), null);
    } catch (RuntimeException e) {
      Throwable cause = e.getCause();
      assertTrue(cause instanceof IOException);
      assertTrue(cause.getMessage().contains("Error canceling token"));
    }
    List<String> logMessages = logCapture.getMessages();
    assertTrue(logMessages.get(0).startsWith(MSG_CANCEL_TOKEN));
    assertTrue(logMessages.get(8).contains("Failing over to "));
    // Determine what the next failover endpoint should be based on the current one
    int nextFailoverEndpoint = logMessages.get(8).contains(endpoints[0]) ? 1 : 0;
    assertTrue(logMessages.get(15).contains("Failing over to " + endpoints[nextFailoverEndpoint]));
    assertTrue(logMessages.get(20).startsWith("Error canceling token: "));
  }

  /**
   * Token renewers should support HA configuration, which includes a comma-separated list of addresses as the value
   * for the IDBroker gateway address property, for token cancelation.
   */
  @Test
  public void testCancelRequestWithHAConfig() throws Exception {
    final String reasonPhrase = "OK";
    final StatusLine statusLine = new BasicStatusLine(HttpVersion.HTTP_1_1, HttpStatus.SC_OK, reasonPhrase);

    final StringEntity responseEntity = createResponseEntity("{\n  \"revoked\": \"true\"\n}\n");

    HttpResponse response = EasyMock.createNiceMock(HttpResponse.class);
    EasyMock.expect(response.getStatusLine()).andReturn(statusLine).anyTimes();
    EasyMock.expect(response.getEntity()).andReturn(responseEntity).anyTimes();
    EasyMock.replay(response);

    final String declaredRenewer = "test-renewer";
    doTestCancelToken(new Text(declaredRenewer),
                      getConfiguration("http://gateway1:8444/gateway/","http://gateway2:8444/gateway/"),
                      response);
    List<String> logMessages = logCapture.getMessages();
    assertTrue(logMessages.get(0).startsWith(MSG_CANCEL_TOKEN));
    assertTrue(logMessages.get(3).contains("Token canceled."));
  }

  @Test
  public void shouldNotRenewNonManagedTokens() throws Exception {
    doTestRenewToken(createTestToken(new Text("test-renewer"), false), getConfiguration(), null, 0L);
    final List<String> logMessages = logCapture.getMessages();
    assertTrue(logMessages.get(0).contains("Skipping renewal of non-managed token"));
  }

  @Test
  public void shouldNotRevokeNonManagedTokens() throws Exception {
    doTestCancelToken(new Text("test-renewer"), getConfiguration(), null, false);
    final List<String> logMessages = logCapture.getMessages();
    assertTrue(logMessages.get(0).contains("Skipping revocation of non-managed token"));
  }

  /**
   * @return The token kind being tested.
   */
  protected abstract Text getTokenKindForTest();

  /**
   * @return An instance of the TokenRenewer implemenation being tested.
   */
  protected abstract AbstractIDBTokenRenewer getTokenRenewerInstance();

  protected abstract Token<T> createTestToken(Text allowedRenewer) throws Exception;

  protected abstract Token<T> createTestToken(Text allowedRenewer, boolean managed) throws Exception;

  protected abstract Configuration getConfiguration();

  protected abstract Configuration getConfiguration(String...gatewayAddresses);

  private void doTestRenewToken(final Text allowedRenewer) throws Exception {
    doTestRenewToken(allowedRenewer, getConfiguration(), null, null);
  }

  private void doTestRenewToken(final Text allowedRenewer, final Configuration conf, final HttpResponse testResponse, final Long expectedUpdatedExpiration)
      throws Exception {
    doTestRenewToken(createTestToken(allowedRenewer), conf, testResponse, expectedUpdatedExpiration);
  }

  private void doTestRenewToken(final Token<T> testToken, final Configuration conf, final HttpResponse testResponse, final Long expectedUpdatedExpiration) throws Exception {
    UserGroupInformation renewer = createTestUser("test-renewer");
    final AbstractIDBTokenRenewer tokenRenewer = getTokenRenewerInstance();
    long expiration = renewer.doAs((PrivilegedAction<Long>) () -> {
      long result;
      try {
        TokenRenewerTestDecorator decorated = new TokenRenewerTestDecorator(getTokenRenewerInstance(), testResponse);
        if (testResponse != null) {
          TestRequestExecutorDecorator testExecutor =
                  new TestRequestExecutorDecorator(decorated.getRequestExecutor(conf),
                          new BasicResponse(testResponse));
          decorated.setRequestExecutor(testExecutor);
        }
        result = decorated.renew(testToken, conf);
      } catch (Exception e) {
        throw new RuntimeException(e);
      }
      return result;
    });

    long expectedExpiration;
    if (expectedUpdatedExpiration != null) {
      expectedExpiration = expectedUpdatedExpiration;
    } else {
      expectedExpiration = tokenRenewer.getTokenExpiration(testToken.decodeIdentifier());
    }
    assertEquals(expectedExpiration, expiration);
  }

  private void doTestCancelToken(final Text allowedRenewer) throws Exception {
    doTestCancelToken(allowedRenewer, null);
  }

  private void doTestCancelToken(final Text allowedRenewer, final HttpResponse testResponse) throws Exception {
    doTestCancelToken(allowedRenewer, getConfiguration(), testResponse);
  }

  private void doTestCancelToken(final Text allowedRenewer, final Configuration conf, final HttpResponse testResponse) throws Exception {
    doTestCancelToken(allowedRenewer, conf, testResponse, true);
  }

  private void doTestCancelToken(final Text allowedRenewer, final Configuration conf, final HttpResponse testResponse, boolean managed) throws Exception {
    UserGroupInformation renewer = createTestUser("test-renewer");
    renewer.doAs((PrivilegedAction<Void>) () -> {
      try {
        TokenRenewerTestDecorator decorated = new TokenRenewerTestDecorator(getTokenRenewerInstance(), testResponse);
        if (testResponse != null) {
          TestRequestExecutorDecorator testExecutor =
                  new TestRequestExecutorDecorator(decorated.getRequestExecutor(conf),
                                                   new BasicResponse(testResponse));
          decorated.setRequestExecutor(testExecutor);
        }
        decorated.cancel(createTestToken(allowedRenewer, managed), conf);
      } catch (Exception e) {
        throw new RuntimeException(e);
      }
      return null;
    });
  }

  private static UserGroupInformation createTestUser(final String username) throws IOException {
    Subject s = new Subject();
    Set<Principal> principals = s.getPrincipals();
    principals.add(new KerberosPrincipal(username));
    return UserGroupInformation.getUGIFromSubject(s);
  }

  private static StringEntity createResponseEntity(final String content) {
    StringEntity responseEntity = new StringEntity(content, StandardCharsets.UTF_8);
    responseEntity.setContentType(MediaType.APPLICATION_JSON);
    return responseEntity;
  }

  class TestAppender extends AppenderSkeleton {
    private final List<String> messages = new ArrayList<>();

    @Override
    public boolean requiresLayout() {
      return false;
    }

    @Override
    protected void append(final LoggingEvent loggingEvent) {
      messages.add(loggingEvent.getRenderedMessage());
    }

    List<String> getMessages() {
      return messages;
    }

    @Override
    public void close() {
    }
  }

  /**
   * Decorator for adding HTTP request handling behavior for testing response handling.
   */
  private static class TokenRenewerTestDecorator extends AbstractIDBTokenRenewer {

    private final AbstractIDBTokenRenewer delegate;
    private final HttpResponse testResponse;

    private RequestExecutor testExecutor;

    TokenRenewerTestDecorator(final AbstractIDBTokenRenewer delegate, final HttpResponse response) {
      this.delegate = delegate;
      this.testResponse = response;
    }

    void setRequestExecutor(RequestExecutor executor) {
      testExecutor = executor;
    }

    @Override
    protected RequestExecutor getRequestExecutor(Configuration conf) {
      return testExecutor != null ? testExecutor : delegate.getRequestExecutor(conf);
    }

    @Override
    public boolean handleKind(Text text) {
      return delegate.handleKind(text);
    }

    @Override
    protected List<String> getGatewayAddressConfigProperty(Configuration config) {
      return delegate.getGatewayAddressConfigProperty(config);
    }

    @Override
    protected String getDelegationTokenPathConfigProperty(Configuration config) {
      return delegate.getDelegationTokenPathConfigProperty(config);
    }

    @Override
    protected String getAccessToken(DelegationTokenIdentifier identifier) {
      return delegate.getAccessToken(identifier);
    }

    @Override
    protected long getTokenExpiration(DelegationTokenIdentifier identifier) {
      return delegate.getTokenExpiration(identifier);
    }

    @Override
    protected RequestErrorHandlingAttributes getRequestErrorHandlingAttributes(Configuration configuration) {
      return delegate.getRequestErrorHandlingAttributes(configuration);
    }

    @Override
    protected boolean isManagedToken(DelegationTokenIdentifier identifier) {
      return delegate.isManagedToken(identifier);
    }
  }

  private static class TestRequestExecutorDecorator implements RequestExecutor {

    private RequestExecutor delegate;

    private Object testResponse;

    TestRequestExecutorDecorator(RequestExecutor delegate, Object testResponse) {
      this.delegate = delegate;
      this.testResponse = testResponse;
    }

    @Override
    public String getEndpoint() {
      return delegate.getEndpoint();
    }

    @Override
    public List<String> getConfiguredEndpoints() {
      return delegate.getConfiguredEndpoints();
    }

    @Override
    public <T> T execute(AbstractCloudAccessBrokerRequest<T> request) {
      return testResponse != null ? (T) testResponse : delegate.execute(request);
    }
  }

}
