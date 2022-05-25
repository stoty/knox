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
package org.apache.knox.gateway.dispatch;

import org.apache.commons.io.IOUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.log4j.MDC;
import org.apache.knox.gateway.SpiGatewayMessages;
import org.apache.knox.gateway.filter.GatewayResponse;
import org.apache.knox.gateway.i18n.messages.MessagesFactory;
import org.apache.http.Header;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpUriRequest;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.Set;

public abstract class AbstractGatewayDispatch implements Dispatch {
  protected static final SpiGatewayMessages LOG = MessagesFactory.get(SpiGatewayMessages.class);

  private static final Set<String> REQUEST_EXCLUDE_HEADERS = new HashSet<>(Arrays.asList("Host", "Authorization", "Content-Length", "Transfer-Encoding"));
  protected static final String REQUEST_ID_HEADER_NAME = "X-Request-Id";
  protected static final String EXPECT_HEADER_NAME = "Expect";
  protected static final String EXPECT_100_CONTINUE = "100-continue";
  protected static final String TRACE_ID = "trace_id";

  protected  HttpClient client;

  @Override
  public void init() {
  }

  protected void writeResponse(HttpServletRequest request, HttpServletResponse response, InputStream stream)
      throws IOException {
    if (response instanceof GatewayResponse) {
      ((GatewayResponse) response).streamResponse(stream);
    } else {
      try(OutputStream output = response.getOutputStream()) {
        IOUtils.copy(stream, output);
      }
    }
  }

  @Override
  public synchronized HttpClient getHttpClient() {
    return client;
  }

  @Override
  public synchronized void setHttpClient(HttpClient client) {
    this.client = client;
  }

  @Override
  public URI getDispatchUrl(HttpServletRequest request) {
    StringBuffer str = request.getRequestURL();
    String query = request.getQueryString();
    if ( query != null ) {
      str.append('?');
      str.append(query);
    }
    return URI.create(str.toString());
  }

  @Override
  public void doGet(URI url, HttpServletRequest request, HttpServletResponse response )
      throws IOException, URISyntaxException {
    response.sendError( HttpServletResponse.SC_METHOD_NOT_ALLOWED );
  }

  @Override
  public void doPost(URI url, HttpServletRequest request, HttpServletResponse response )
      throws IOException, URISyntaxException {
    response.sendError( HttpServletResponse.SC_METHOD_NOT_ALLOWED );
  }

  @Override
  public void doPut(URI url, HttpServletRequest request, HttpServletResponse response )
      throws IOException, URISyntaxException {
    response.sendError( HttpServletResponse.SC_METHOD_NOT_ALLOWED );
  }

  @Override
  public void doPatch(URI url, HttpServletRequest request, HttpServletResponse response )
      throws IOException, URISyntaxException {
    response.sendError( HttpServletResponse.SC_METHOD_NOT_ALLOWED );
  }

  @Override
  public void doDelete(URI url, HttpServletRequest request, HttpServletResponse response )
      throws IOException, URISyntaxException {
    response.sendError( HttpServletResponse.SC_METHOD_NOT_ALLOWED );
  }

  @Override
  public void doOptions(URI url, HttpServletRequest request, HttpServletResponse response )
      throws IOException, URISyntaxException {
    response.sendError( HttpServletResponse.SC_METHOD_NOT_ALLOWED );
  }

  /**
   * @since 0.14.0
   */
  @Override
  public void doHead(URI url, HttpServletRequest request, HttpServletResponse response )
      throws IOException, URISyntaxException {
    response.sendError( HttpServletResponse.SC_METHOD_NOT_ALLOWED );
  }

  public void copyRequestHeaderFields(HttpUriRequest outboundRequest, HttpServletRequest inboundRequest) {
    copyRequestHeaderFields(outboundRequest, inboundRequest, false);
  }

  public void copyRequestHeaderFields(HttpUriRequest outboundRequest, HttpServletRequest inboundRequest, boolean shouldAddExpect100Header) {
    Enumeration<String> headerNames = inboundRequest.getHeaderNames();
    /**
     Add X-Request-Id headers to outgoing requests.
     Only do this when
     1. incoming request does not have X-Request-Id header (if it has no need to add)
     2. This header is not in exclude header list
     3. This header is present in the MDC context
     **/
    if(StringUtils.isBlank(inboundRequest.getHeader(REQUEST_ID_HEADER_NAME)) &&
            !getOutboundRequestExcludeHeaders().contains( REQUEST_ID_HEADER_NAME ) &&
            !StringUtils.isBlank((String)MDC.get(TRACE_ID))) {
      outboundRequest.addHeader( REQUEST_ID_HEADER_NAME,  (String)MDC.get(TRACE_ID));
    }
    while( headerNames.hasMoreElements() ) {
      String name = headerNames.nextElement();
      if ( !outboundRequest.containsHeader( name )
          && !getOutboundRequestExcludeHeaders().contains( name ) ) {
        String value = inboundRequest.getHeader( name );
        outboundRequest.addHeader( name, value );
      }
    }

    if (shouldAddExpect100Header && !getOutboundRequestExcludeHeaders().contains(EXPECT_HEADER_NAME) && !requestHasExpect100(outboundRequest)) {
      outboundRequest.addHeader(EXPECT_HEADER_NAME, EXPECT_100_CONTINUE);
      LOG.addedExpect100Continue();
    }
  }

  private boolean requestHasExpect100(HttpUriRequest request) {
    final Header[] expectHeaders = request.getHeaders(EXPECT_HEADER_NAME);
    if (expectHeaders != null) {
      for (Header expectHeader: expectHeaders) {
        if (EXPECT_100_CONTINUE.equalsIgnoreCase(expectHeader.getValue())) {
          return true;
        }
      }
    }
    return false;
  }

  public Set<String> getOutboundRequestExcludeHeaders() {
    return REQUEST_EXCLUDE_HEADERS;
  }

  protected void encodeUnwiseCharacters(StringBuffer str) {
    int pipe = str.indexOf("|");
    while (pipe > -1) {
      str.replace(pipe, pipe+1, "%7C");
      pipe = str.indexOf("|", pipe+1);
    }
    int dq = str.indexOf("\"");
    while (dq > -1) {
      str.replace(dq, dq+1, "%22");
      dq = str.indexOf("\"", dq+1);
    }
    int lessThan = str.indexOf("<");
    while (lessThan > -1) {
      str.replace(lessThan, lessThan+1, "%3C");
      lessThan = str.indexOf("<", lessThan+1);
    }
    int greaterThan = str.indexOf(">");
    while (greaterThan > -1) {
      str.replace(greaterThan, greaterThan+1, "%3E");
      greaterThan = str.indexOf(">", greaterThan+1);
    }
    int space = str.indexOf(" ");
    while (space > -1) {
      str.replace(space, space+1, "%20");
      space = str.indexOf(">", space+1);
    }
  }
}
