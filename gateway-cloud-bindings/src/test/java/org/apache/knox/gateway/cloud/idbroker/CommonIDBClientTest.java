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
package org.apache.knox.gateway.cloud.idbroker;

import org.apache.hadoop.conf.Configuration;
import org.apache.http.Header;
import org.apache.http.HeaderElement;
import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.HttpStatus;
import org.apache.http.NameValuePair;
import org.apache.http.StatusLine;
import org.apache.knox.gateway.cloud.idbroker.common.RequestExecutor;
import org.apache.knox.gateway.shell.BasicResponse;
import org.apache.knox.gateway.shell.CloudAccessBrokerSession;
import org.apache.knox.gateway.shell.ErrorResponse;
import org.easymock.EasyMock;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import javax.ws.rs.core.MediaType;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

import static org.easymock.EasyMock.anyObject;

public class CommonIDBClientTest {

  @Rule
  public ExpectedException exceptionRule = ExpectedException.none();

  @Test
  public void testFetchCredentialsWithErrorResponseJSON() throws Exception {
    final String entityContent = "{ \"error\": \"test error\" }";

    exceptionRule.expect(IOException.class);
    exceptionRule.expectMessage("test error");

    doTestFetchCredentialsWithErrorResponse(MediaType.APPLICATION_JSON, entityContent);
  }

  @Test(expected = ErrorResponse.class)
  public void testFetchCredentialsWithErrorResponseOther() throws Exception {
    final String entityContent = "Bad request: token has expired";
    doTestFetchCredentialsWithErrorResponse(MediaType.TEXT_PLAIN, entityContent);
  }


  private void doTestFetchCredentialsWithErrorResponse(final String contentType, final String entityContent)
      throws Exception {

    StatusLine status = EasyMock.createNiceMock(StatusLine.class);
    EasyMock.expect(status.getStatusCode()).andReturn(HttpStatus.SC_BAD_REQUEST).anyTimes();
    EasyMock.replay(status);

    HeaderElement headerElement = EasyMock.createNiceMock(HeaderElement.class);
    EasyMock.expect(headerElement.getName()).andReturn("Content-type").anyTimes();
    EasyMock.expect(headerElement.getValue()).andReturn(contentType).anyTimes();
    EasyMock.expect(headerElement.getParameters()).andReturn(new NameValuePair[]{}).anyTimes();
    EasyMock.replay(headerElement);
    HeaderElement[] contentTypeElements = new HeaderElement[]{ headerElement };

    Header contentTypeHeader = EasyMock.createNiceMock(Header.class);
    EasyMock.expect(contentTypeHeader.getValue()).andReturn(contentType).anyTimes();
    EasyMock.expect(contentTypeHeader.getElements()).andReturn(contentTypeElements).anyTimes();
    EasyMock.replay(contentTypeHeader);

    HttpEntity entity = EasyMock.createNiceMock(HttpEntity.class);
    EasyMock.expect(entity.getContentType()).andReturn(contentTypeHeader).anyTimes();
    ByteArrayInputStream contentStream = new ByteArrayInputStream(entityContent.getBytes(StandardCharsets.UTF_8));
    EasyMock.expect(entity.getContent()).andReturn(contentStream).anyTimes();
    EasyMock.replay(entity);

    HttpResponse response = EasyMock.createNiceMock(HttpResponse.class);
    EasyMock.expect(response.getStatusLine()).andReturn(status).anyTimes();
    EasyMock.expect(response.getEntity()).andReturn(entity).anyTimes();
    EasyMock.replay(response);

    ErrorResponse errResponse = EasyMock.createNiceMock(ErrorResponse.class);
    EasyMock.expect(errResponse.getResponse()).andReturn(response).anyTimes();
    EasyMock.replay(errResponse);

    RequestExecutor executor = EasyMock.createNiceMock(RequestExecutor.class);
    EasyMock.expect(executor.execute(anyObject())).andThrow(errResponse).anyTimes();
    EasyMock.replay(executor);

    AbstractIDBClient client = new TestIDBClient(executor);

    CloudAccessBrokerSession session = EasyMock.createNiceMock(CloudAccessBrokerSession.class);
    EasyMock.expect(session.base()).andReturn("http://someaddress").anyTimes();
    EasyMock.replay(session);

    client.fetchCloudCredentials(session);
  }

  private static class TestIDBClient extends AbstractIDBClient<String> {

    TestIDBClient(RequestExecutor executor) {
      super();
      this.requestExecutor = executor;
    }

    @Override
    protected boolean getOnlyUser(Configuration configuration) {
      return false;
    }

    @Override
    protected boolean getOnlyGroups(Configuration configuration) {
      return false;
    }

    @Override
    protected String getSpecificRole(Configuration configuration) {
      return null;
    }

    @Override
    protected String getSpecificGroup(Configuration configuration) {
      return null;
    }

    @Override
    protected String getTruststorePath(Configuration configuration) {
      return null;
    }

    @Override
    protected char[] getTruststorePassword(Configuration configuration) throws IOException {
      return new char[0];
    }

    @Override
    protected boolean getUseCertificateFromDT(Configuration configuration) {
      return false;
    }

    @Override
    protected String getDelegationTokensURL(Configuration configuration) {
      return null;
    }

    @Override
    protected String getCredentialsURL(Configuration configuration) {
      return null;
    }

    @Override
    protected String getCredentialsType(Configuration configuration) {
      return null;
    }

    @Override
    protected String[] getGatewayAddress(Configuration configuration) {
      return new String[0];
    }

    @Override
    protected String getUsername(Configuration configuration) {
      return null;
    }

    @Override
    protected String getUsernamePropertyName() {
      return null;
    }

    @Override
    protected String getPassword(Configuration configuration) {
      return null;
    }

    @Override
    protected String getPasswordPropertyName() {
      return null;
    }

    @Override
    public String extractCloudCredentialsFromResponse(BasicResponse basicResponse) throws IOException {
      return null;
    }

    @Override
    protected boolean preferKnoxTokenOverKerberos(Configuration configuration) {
      return true;
    }
  }

}
