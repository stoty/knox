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
import org.apache.log4j.AppenderSkeleton;
import org.apache.log4j.Level;
import org.apache.log4j.Logger;
import org.apache.log4j.spi.LoggingEvent;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import javax.security.auth.Subject;
import javax.security.auth.kerberos.KerberosPrincipal;
import java.io.IOException;
import java.security.Principal;
import java.security.PrivilegedAction;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

/**
 * Base class for IDBroker delegation token renewer implementations.
 */
public abstract class AbstractIDBTokenRenewerTest<T extends DelegationTokenIdentifier> {

  private static final String RENEWER_MISMATCH_REGEX =
                                    "The user \\(.*\\) does not match the renewer declared for the token: .*";

  private static final String MSG_RENEW_TOKEN = "Renew token";

  private static final String MSG_CANCEL_TOKEN = "Cancel token";

  private static final String MSG_ERR_NO_RENEWER_FOR_TOKEN =
                                    "Operation not permitted. No renewer is specified in the identifier.";

  private static final String MSG_EXPIRATION_UPDATED_0 = "Updated token expiration: 0";

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

  @Test
  public void testMatchingRenewerForRenewal() throws Exception {
    final String declaredRenewer = "test-renewer";
    doTestRenewToken(new Text(declaredRenewer));
    List<String> logMessages = logCapture.getMessages();
    assertEquals(MSG_RENEW_TOKEN, logMessages.get(0));
    assertTrue(logMessages.get(4).contains("Error renewing token: "));
  }

  @Test
  public void testInvalidRenewer() throws Exception {
    final String declaredRenewer = "validRenewer";
    doTestRenewToken(new Text(declaredRenewer));
    List<String> logMessages = logCapture.getMessages();
    assertEquals(MSG_RENEW_TOKEN, logMessages.get(0));
    assertTrue(logMessages.get(2).matches(RENEWER_MISMATCH_REGEX));
    assertEquals(MSG_EXPIRATION_UPDATED_0, logMessages.get(3));
  }

  @Test
  public void testRenewalWithNullRenewerSpecifiedOnToken() throws Exception {
    doTestRenewToken(null);
    List<String> logMessages = logCapture.getMessages();
    assertEquals(MSG_RENEW_TOKEN, logMessages.get(0));
    assertEquals(MSG_ERR_NO_RENEWER_FOR_TOKEN, logMessages.get(2));
    assertEquals(MSG_EXPIRATION_UPDATED_0, logMessages.get(3));
  }

  @Test
  public void testRenewalWithEmptyRenewerSpecifiedOnToken() throws Exception {
    doTestRenewToken(new Text());
    List<String> logMessages = logCapture.getMessages();
    assertEquals(MSG_RENEW_TOKEN, logMessages.get(0));
    assertEquals(MSG_ERR_NO_RENEWER_FOR_TOKEN, logMessages.get(2));
    assertEquals(MSG_EXPIRATION_UPDATED_0, logMessages.get(3));
  }

  @Test
  public void testMatchingRenewerForCancel() throws Exception {
    final String declaredRenewer = "test-renewer";
    doTestCancelToken(new Text(declaredRenewer));
    List<String> logMessages = logCapture.getMessages();
    assertEquals(MSG_CANCEL_TOKEN, logMessages.get(0));
    assertTrue(logMessages.get(4).contains("Error cancelling token: "));
  }

  @Test
  public void testInvalidCancelRenewer() throws Exception {
    final String declaredRenewer = "validRenewer";
    doTestCancelToken(new Text(declaredRenewer));
    List<String> logMessages = logCapture.getMessages();
    assertEquals(MSG_CANCEL_TOKEN, logMessages.get(0));
    assertTrue(logMessages.get(2).matches(RENEWER_MISMATCH_REGEX));
  }

  @Test
  public void testCancelWithNullRenewerSpecifiedOnToken() throws Exception {
    doTestCancelToken(null);
    List<String> logMessages = logCapture.getMessages();
    assertEquals(MSG_CANCEL_TOKEN, logMessages.get(0));
    assertEquals(MSG_ERR_NO_RENEWER_FOR_TOKEN, logMessages.get(2));
  }

  @Test
  public void testCancelWithEmptyRenewerSpecifiedOnToken() throws Exception {
    doTestCancelToken(new Text());
    List<String> logMessages = logCapture.getMessages();
    assertEquals(MSG_CANCEL_TOKEN, logMessages.get(0));
    assertEquals(MSG_ERR_NO_RENEWER_FOR_TOKEN, logMessages.get(2));
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

  protected abstract Configuration getConfiguration();

  private void doTestRenewToken(final Text allowedRenewer) throws Exception {
    UserGroupInformation renewer = createTestUser("test-renewer");
    long expiration = renewer.doAs((PrivilegedAction<Long>) () -> {
      long result;
      try {
        result = getTokenRenewerInstance().renew(createTestToken(allowedRenewer), getConfiguration());
      } catch (Exception e) {
        throw new RuntimeException(e);
      }
      return result;
    });
    assertEquals(0, expiration);
  }

  private void doTestCancelToken(final Text allowedRenewer) throws Exception {
    UserGroupInformation renewer = createTestUser("test-renewer");
    renewer.doAs((PrivilegedAction<Void>) () -> {
      try {
        getTokenRenewerInstance().cancel(createTestToken(allowedRenewer), getConfiguration());
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

}
