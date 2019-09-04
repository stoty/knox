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
package org.apache.knox.gateway.shell.idbroker;

import org.apache.http.Header;
import org.apache.http.HeaderIterator;
import org.apache.http.HttpEntity;
import org.apache.http.HttpRequest;
import org.apache.http.HttpStatus;
import org.apache.http.ProtocolVersion;
import org.apache.http.StatusLine;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.params.HttpParams;
import org.apache.knox.gateway.shell.CloudAccessBrokerSession;
import org.apache.knox.gateway.shell.TestErrorResponse;

import java.io.IOException;
import java.util.Locale;

public abstract class AbstractBrokenCredentialsRequest extends Get.Request {

  private int statusCode;

  protected AbstractBrokenCredentialsRequest(CloudAccessBrokerSession session, int statusCode) {
    super(session);
    this.statusCode = statusCode;
  }

  @Override
  protected CloseableHttpResponse execute(HttpRequest request) {
    throw new TestErrorResponse("Test Error Response ", new TestHttpResponse(statusCode));
  }

  public int getStatusCode() {
    return statusCode;
  }

  private static final class TestHttpResponse implements CloseableHttpResponse {

    StatusLine statusLine;

    public TestHttpResponse(final int statusCode) {
      super();

      statusLine = new StatusLine() {
        @Override
        public ProtocolVersion getProtocolVersion() {
          return new ProtocolVersion("HTTP", 1, 1);
        }

        @Override
        public int getStatusCode() {
          return statusCode;
        }

        @Override
        public String getReasonPhrase() {
          return "Not Found";
        }
      };
    }

    @Override
    public StatusLine getStatusLine() {
      return statusLine;
    }

    @Override
    public void close() throws IOException {
    }

    @Override
    public void setStatusLine(StatusLine statusLine) {
    }

    @Override
    public void setStatusLine(ProtocolVersion protocolVersion, int i) {
    }

    @Override
    public void setStatusLine(ProtocolVersion protocolVersion, int i, String s) {
    }

    @Override
    public void setStatusCode(int i) throws IllegalStateException {
    }

    @Override
    public void setReasonPhrase(String s) throws IllegalStateException {
    }

    @Override
    public HttpEntity getEntity() {
      return null;
    }

    @Override
    public void setEntity(HttpEntity httpEntity) {
    }

    @Override
    public Locale getLocale() {
      return null;
    }

    @Override
    public void setLocale(Locale locale) {
    }

    @Override
    public ProtocolVersion getProtocolVersion() {
      return null;
    }

    @Override
    public boolean containsHeader(String s) {
      return false;
    }

    @Override
    public Header[] getHeaders(String s) {
      return new Header[0];
    }

    @Override
    public Header getFirstHeader(String s) {
      return null;
    }

    @Override
    public Header getLastHeader(String s) {
      return null;
    }

    @Override
    public Header[] getAllHeaders() {
      return new Header[0];
    }

    @Override
    public void addHeader(Header header) {
    }

    @Override
    public void addHeader(String s, String s1) {
    }

    @Override
    public void setHeader(Header header) {
    }

    @Override
    public void setHeader(String s, String s1) {
    }

    @Override
    public void setHeaders(Header[] headers) {
    }

    @Override
    public void removeHeader(Header header) {
    }

    @Override
    public void removeHeaders(String s) {
    }

    @Override
    public HeaderIterator headerIterator() {
      return null;
    }

    @Override
    public HeaderIterator headerIterator(String s) {
      return null;
    }

    @Override
    public HttpParams getParams() {
      return null;
    }

    @Override
    public void setParams(HttpParams httpParams) {
    }
  }
}
