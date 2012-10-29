/**
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
package org.apache.hadoop.gateway.util.urltemplate;

import java.net.URI;
import java.net.URISyntaxException;

public class Rewriter {

  public static URI rewrite( URI inputUri, Template inputTemplate, Template outputTemplate, Resolver resolver )
      throws URISyntaxException {
    return new Rewriter().rewriteUri( inputUri, inputTemplate, outputTemplate, resolver );
  }

  public URI rewriteUri( URI inputUri, Template inputTemplate, Template outputTemplate, Resolver resolver )
      throws URISyntaxException {
    Template inputUriTemplate = Parser.parse( inputUri.toString() );
    Matcher<Void> matcher = new Matcher<Void>( inputTemplate, null );
    Matcher<Void>.Match match = matcher.match( inputUriTemplate );
    Params params = match.getParams();
    URI outputUri = Expander.expand( outputTemplate, params );
    return outputUri;
  }

}
