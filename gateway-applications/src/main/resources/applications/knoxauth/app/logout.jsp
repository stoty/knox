<!--
  Licensed to the Apache Software Foundation (ASF) under one or more
  contributor license agreements.  See the NOTICE file distributed with
  this work for additional information regarding copyright ownership.
  The ASF licenses this file to You under the Apache License, Version 2.0
  (the "License"); you may not use this file except in compliance with
  the License.  You may obtain a copy of the License at
      http://www.apache.org/licenses/LICENSE-2.0
  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
-->
<%@ page import="java.util.Collection" %>
<%@ page import="java.util.Map" %>
<%@ page import="org.apache.knox.gateway.topology.Topology" %>
<%@ page import="org.apache.knox.gateway.topology.Service" %>
<%@ page import="org.apache.knox.gateway.util.RegExUtils" %>
<%@ page import="org.apache.knox.gateway.util.WhitelistUtils" %>
<%@ page import="org.apache.knox.gateway.config.GatewayConfig" %>
<%@ page import="java.net.MalformedURLException" %>
<%@ page import="org.apache.knox.gateway.util.Urls" %>

<!DOCTYPE html>
<!--[if lt IE 7]><html class="no-js lt-ie9 lt-ie8 lt-ie7"><![endif]-->
<!--[if IE 7]><html class="no-js lt-ie9 lt-ie8"><![endif]-->
<!--[if IE 8]><html class="no-js lt-ie9"><![endif]-->
<!--[if gt IE 8]><!-->
<html class="no-js">
    <!--<![endif]-->
    <head>
        <meta charset="utf-8">
        <meta http-equiv="X-UA-Compatible" content="IE=edge,chrome=1">
        <meta name="description" content="">
        <meta name="viewport" content="width=device-width">
        <meta http-equiv="Content-Type" content="text/html;charset=utf-8"/>
        <meta http-equiv="Cache-Control" content="no-cache, no-store, must-revalidate">
        <meta http-equiv="Pragma" content="no-cache">
        <meta http-equiv="Expires" content="0">

        <link rel="shortcut icon" href="images/favicon.ico">
        <link href="styles/bootstrap.min.css" media="all" rel="stylesheet" type="text/css" id="bootstrap-css">
        <link href="styles/login.css" media="all" rel="stylesheet" type="text/css" >

        <script src="libs/bower/jquery/js/jquery-3.5.1.min.js" ></script>

        <script type="text/javascript" src="js/knoxauth.js"></script>
        <script type="text/javascript">
           $(function() {
                var updateBoxPosition = function() {
                    $('#signin-container').css({
                        'margin-top' : ($(window).height() - $('#signin-container').height()) / 2
                    });
                };
                $(window).resize(updateBoxPosition);
                setTimeout(updateBoxPosition, 50);
            });
        </script>
    <%
        String originalUrl = request.getParameter("originalUrl");
        Topology topology = (Topology)request.getSession().getServletContext().getAttribute("org.apache.knox.gateway.topology");
        String whitelist = null;
        String cookieName = null;
        GatewayConfig gatewayConfig =
                (GatewayConfig) request.getServletContext().
                getAttribute(GatewayConfig.GATEWAY_CONFIG_ATTRIBUTE);
        String globalLogoutPageURL = gatewayConfig.getGlobalLogoutPageUrl();
        String globalLogoutRedirect = gatewayConfig.getGlobalLogoutRedirect();
        Collection<Service> services = topology.getServices();
        for (Service service : services) {
          if (service.getRole().equals("KNOXSSO")) {
            Map<String, String> params = service.getParams();
            whitelist = params.get("knoxsso.redirect.whitelist.regex");
            // LJM TODO: get cookie name and possibly domain prefix info for use in logout
            cookieName = params.get("knoxsso.cookie.name");
            if (cookieName == null) {
                cookieName = "hadoop-jwt";
            }
          }
          break;
        }
        if (whitelist == null) {
            whitelist = WhitelistUtils.getDispatchWhitelist(request);
            if (whitelist == null) {
                whitelist = "";
            }
        }

        boolean validRedirect = false;
        String origUrl = request.getParameter("originalUrl");
        String del = "?";
        if (origUrl != null && origUrl.contains("?")) {
          del = "&";
        }
        if (origUrl != null) {
          validRedirect = RegExUtils.checkWhitelist(whitelist, origUrl);
        }
        if (("1".equals(request.getParameter("returnToApp")))) {
          if (validRedirect) {
          	response.setStatus(HttpServletResponse.SC_MOVED_PERMANENTLY);
          	response.setHeader("Location",originalUrl + del + "refresh=1");
            return;
          }
        }
        else if (("1".equals(request.getParameter("globalLogout")))) {
          response.setStatus(HttpServletResponse.SC_TEMPORARY_REDIRECT);
          response.setHeader("Location", globalLogoutPageURL);
          return;
        }
    %>
  </head>
  
  <body class="login" style="">
    <div id="signin-container" class="page-wrapper">
      <div class="login-wrapper">
        <div class="login-pane-wrapper">
          <div class="login-img">
            <div class="logo"></div>
          </div>
        <%
            if (validRedirect) {
        %>
          <div class="login-controls">
            <h1 >Session Termination</h1>
              <form>
                  <div>
                Your session has timed out or you have attempted to logout of an application
                that is participating in SSO. You may establish a new session by returning to
                the application. If your previously established SSO session is still valid then
                you will likely be automatically logged into your application. Otherwise, you
                will be required to login again.
                <br />
                <a href="?returnToApp=1&originalUrl=<%= originalUrl %>" style="color: #06A">Return to Application</a>
              </div>
              </form>

        <%
            if (globalLogoutPageURL != null && !globalLogoutPageURL.isEmpty()) {
        %>

              <form method="POST" action="#">
                <div>
                If you would like to logout of the Cloudera CDP session, you need to do so from
                the SSO provider. Subsequently, authentication will be required to access
                any SSO protected resources. Note that this may or may not invalidate any previously
                established application sessions. Application sessions are subject to their own application
                specific session cookies and timeouts.
                </div>
                <input type="hidden" name="globalLogout" value="1" id="globalLogoutUrl"/>
                <input type="hidden" name="logoutRedirect" value="<%=globalLogoutRedirect%>" id="globalLogoutRedirect">
                <button type="submit" style="background: none!important; border: none; padding: 0!important; color: #06A; text-decoration: none; cursor: pointer;">Logout from CDP</button>
              </form>

        <%
            }
        } 
        else {
        %>
        <div style="background: gray;text-color: white;text-align:center;">
          <h1 style="color: red;">ERROR</h1>
          <div style="background: white;" class="l-logo">
          </div>
          <p style="color: white;display: block">Invalid Redirect: Possible Phishing Attempt</p>
        <%
        }
        %>
            </div>
          </div>
        </div>
      </div>
    </div>
  </body>
</html>
