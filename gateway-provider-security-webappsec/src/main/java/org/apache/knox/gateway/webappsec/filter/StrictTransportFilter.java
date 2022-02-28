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
package org.apache.knox.gateway.webappsec.filter;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpServletResponseWrapper;

/**
 * This filter protects proxied webapps from protocol downgrade attacks
 * and cookie hijacking.
 */
public class StrictTransportFilter implements Filter {
  private static final String STRICT_TRANSPORT = "Strict-Transport-Security";
  private static final String CUSTOM_HEADER_PARAM = "strict.transport";
  public static final String DEFAULT_STS_DIRECTIVES = "max-age=31536000; includeSubDomains";

  private String option = DEFAULT_STS_DIRECTIVES;

  @Override
  public void destroy() {
  }

  @Override
  public void doFilter(ServletRequest req, ServletResponse res,
      FilterChain chain) throws IOException, ServletException {
    ((HttpServletResponse) res).setHeader(STRICT_TRANSPORT, option);
    chain.doFilter(req, new StrictTransportResponseWrapper((HttpServletResponse) res));
  }

  @Override
  public void init(FilterConfig config) throws ServletException {
    String customOption = config.getInitParameter(CUSTOM_HEADER_PARAM);
    if (customOption != null) {
      option = customOption;
    }
  }

  public class StrictTransportResponseWrapper extends HttpServletResponseWrapper {
    @Override
    public void addHeader(String name, String value) {
      // don't allow additional values to be added to
      // the configured options value in topology
      if (!name.equals(STRICT_TRANSPORT)) {
        super.addHeader(name, value);
      }
    }

    @Override
    public void setHeader(String name, String value) {
      // don't allow overwriting of configured value
      if (!name.equals(STRICT_TRANSPORT)) {
        super.setHeader(name, value);
      }
    }

    public StrictTransportResponseWrapper(HttpServletResponse response) {
        super(response);
    }

    @Override
    public String getHeader(String name) {
        String headerValue;
        if (name.equals(STRICT_TRANSPORT)) {
            headerValue = option;
        }
        else {
          headerValue = super.getHeader(name);
        }
        return headerValue;
    }

    @Override
    public Collection<String> getHeaderNames() {
        List<String> names = (List<String>) super.getHeaderNames();
        if (names == null) {
          names = new ArrayList<>();
        }
        names.add(STRICT_TRANSPORT);
        return names;
    }

    @Override
    public Collection<String> getHeaders(String name) {
        List<String> values = (List<String>) super.getHeaders(name);
        if (name.equals(STRICT_TRANSPORT)) {
          if (values == null) {
            values = new ArrayList<>();
          }
          values.add(option);
        }
        return values;
    }
  }
}
