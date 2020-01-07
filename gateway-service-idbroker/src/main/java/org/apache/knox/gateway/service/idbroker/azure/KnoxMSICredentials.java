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
package org.apache.knox.gateway.service.idbroker.azure;

import com.jayway.jsonpath.JsonPath;
import com.jayway.jsonpath.PathNotFoundException;
import com.microsoft.azure.AzureEnvironment;
import com.microsoft.azure.credentials.AzureTokenCredentials;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.exception.ExceptionUtils;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPatch;
import org.apache.http.entity.ContentType;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.protocol.HTTP;
import org.apache.knox.gateway.i18n.messages.MessagesFactory;

import javax.ws.rs.HttpMethod;
import javax.ws.rs.WebApplicationException;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Random;
import java.util.Set;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReadWriteLock;
import java.util.concurrent.locks.ReentrantReadWriteLock;
import java.util.stream.Collectors;

/**
 * Get access token for Managed Service Identity. This class is modeled after
 * com.microsoft.azure.credentials.MSICredentials and tailored to return other
 * relevant token information.
 */
public class KnoxMSICredentials extends AzureTokenCredentials {
  private static final String API_VERSION_2018_02 = "2018-02-01";
  private static final String API_VERSION_2018_06 = "2018-06-01";
  private static final String IMDS_ENDPOINT = "169.254.169.254";
  private static final String AZURE_MANAGEMENT_ENDPOINT = "management.azure.com";

  private static final AzureClientMessages LOG = MessagesFactory.get(AzureClientMessages.class);
  private static final Random RANDOM = new Random();

  private static final List<Integer> retrySlots = Arrays.asList(
      1, 1, 2, 3, 5, 8, 13, 21, 34, 55, 89, 144, 233, 377, 610, 987, 1597, 2584, 4181, 6765);
  private static final int maxRetry = retrySlots.size();

  private final String resource;
  private String objectId;
  private String clientId;
  private String identityId;

  private final ReadWriteLock readWriteLock = new ReentrantReadWriteLock();
  private final Lock readLock = readWriteLock.readLock();
  private final Lock writeLock = readWriteLock.writeLock();

  /* create an instance */
  public KnoxMSICredentials() {
    this(AzureEnvironment.AZURE);
  }

  public KnoxMSICredentials(final AzureEnvironment environment) {
    super(environment, null);
    this.resource = environment.managementEndpoint();
  }

  public KnoxMSICredentials withObjectId(String objectId) {
    this.objectId = objectId;
    this.clientId = null;
    this.identityId = null;
    return this;
  }

  public KnoxMSICredentials withClientId(String clientId) {
    this.clientId = clientId;
    this.objectId = null;
    this.identityId = null;
    return this;
  }

  public KnoxMSICredentials withIdentityId(String identityId) {
    this.identityId = identityId;
    this.clientId = null;
    this.objectId = null;
    return this;
  }

  @Override
  public String getToken(String tokenAudience) throws IOException {
    /*
     * Here are are not trying the MSI extension installed on the VM
     * but going for the wellknown IMDS endpoint.
     */
    try {
      return getTokenFromIMDSEndpoint(
          tokenAudience == null ? this.resource : tokenAudience);
    } catch (InterruptedException e) {
      throw new RuntimeException(e);
    }
  }

  /**
   * Get compute instance metadata for VM from the IMDS endpoint
   *
   * @param resource name of resource
   * @return returns the metadata for given resource
   * @throws IOException
   * @throws InterruptedException
   */
  public String getComputeInstanceMetadata(final String resource)
      throws InterruptedException {

    try {
      final String payload = "api-version=" + URLEncoder.encode(API_VERSION_2018_02,
          StandardCharsets.UTF_8.name());

      final Map<String, String> headers = new HashMap<>();
      headers.put("Metadata", "true");

      /* if no resource is defined get compute metadata for self */
      if (StringUtils.isBlank(resource)) {
        return httpRequest(HttpMethod.GET, String.format(Locale.ROOT,
            "http://" + IMDS_ENDPOINT + "/metadata/instance/compute?%s",
            payload), headers, null);
      } else {
        return httpRequest(HttpMethod.GET, String.format(Locale.ROOT,
            "http://" + IMDS_ENDPOINT + "/metadata/instance/compute/%s?%s",
            resource, payload), headers, null);
      }
    } catch (final IOException exception) {
      throw new RuntimeException(exception);
    }
  }

  /**
   * Attach the given identity list to VM (VM, the process is running on)
   * <b>NOTE:</b> identity list should contains ALL identities (new and old)
   *
   * @param resourceName full resource name of the VM to attach identities to
   *                     (self)
   * @param identities   identity list in Json format.
   * @param accessToken  access token
   * @return
   * @throws IOException
   * @throws InterruptedException
   */
  public String attachIdentities(final String resourceName,
      final String identities, final String accessToken) {
    writeLock.lock();
    try {
      String payload = "api-version=" + URLEncoder.encode(API_VERSION_2018_06,
          StandardCharsets.UTF_8.name());

      final Map<String, String> headers = new HashMap<>();
      headers.put(HTTP.CONTENT_TYPE, MediaType.APPLICATION_JSON);
      headers.put("Authorization", "Bearer " + accessToken);

      return httpPatchRequest(String
          .format(Locale.ROOT, "https://" + AZURE_MANAGEMENT_ENDPOINT + "%s?%s",
              resourceName, payload), headers, identities);
    } catch (final IOException | PathNotFoundException exception) {
      throw new RuntimeException(exception);
    } finally {
      writeLock.unlock();
    }
  }

  /**
   * Get a Json string list of all assigned identities for a VM.
   *
   * @param resourceName
   * @param accessToken
   * @return Set of user identities attached to the VM if present, else empty
   * list.
   * @throws InterruptedException
   */
  public Set<String> getAssignedUserIdentityList(final String resourceName,
      final String accessToken) throws InterruptedException {
    readLock.lock();
    try {
      final Map<String, String> headers = new HashMap<>();
      headers.put("Authorization", "Bearer " + accessToken);

      String payload = "api-version=" + URLEncoder.encode(API_VERSION_2018_06,
          StandardCharsets.UTF_8.name());
      final String response = httpRequest(HttpMethod.GET, String
          .format(Locale.ROOT,
              "https://" + AZURE_MANAGEMENT_ENDPOINT + "/%s?%s", resourceName,
              payload), headers, null);


      Map<String, Object> userAssignedIdentities = new HashMap<>();
      try {
        userAssignedIdentities = JsonPath.read(response, "$.identity.userAssignedIdentities");
      } catch(final PathNotFoundException e) {
        /* empty identity */
      }

      return userAssignedIdentities.keySet();
    } catch (IOException exception) {
      throw new RuntimeException(exception);
    } finally {
      readLock.unlock();
    }
  }

  /* Get token from well known IMDS endpoint */
  private String getTokenFromIMDSEndpoint(final String tokenAudience)
      throws InterruptedException {
    try {
      final StringBuilder payload = new StringBuilder()
                                        .append("api-version=")
                                        .append(URLEncoder.encode(API_VERSION_2018_02, StandardCharsets.UTF_8.name()))
                                        .append("&resource=")
                                        .append(URLEncoder.encode(tokenAudience, StandardCharsets.UTF_8.name()));
      if (this.objectId != null) {
        payload
            .append("&object_id=")
            .append(URLEncoder.encode(this.objectId, StandardCharsets.UTF_8.name()));
      } else if (this.clientId != null) {
        payload
            .append("&client_id=")
            .append(URLEncoder.encode(this.clientId, StandardCharsets.UTF_8.name()));
      } else if (this.identityId != null) {
        payload
            .append("&msi_res_id=")
            .append(URLEncoder.encode(this.identityId, StandardCharsets.UTF_8.name()));
      }

      final Map<String,String> headers = new HashMap<>();
      headers.put("Metadata", "true");

      return httpRequest(HttpMethod.GET, String.format(Locale.ROOT,
          "http://" + IMDS_ENDPOINT + "/metadata/identity/oauth2/token?%s",
          payload.toString()), headers, null);
    } catch (IOException exception) {
      throw new RuntimeException(exception);
    }
  }

  /**
   * Make a HTTP request to IMDS endpoint with a given payload.
   *
   * @param imdsPayload payload
   * @return returns response from IMDS
   * @throws IOException
   * @throws InterruptedException
   */
  private String httpRequest(final String method, final String imdsPayload,
      final Map<String, String> headers, final String postBody)
      throws IOException, InterruptedException {

    final int imdsUpgradeTimeInMs = 70 * 1000;
    int retry = 1;
    int responseCode = 0;
    String error = "";
    while (retry <= maxRetry) {
      final URL url = new URL(imdsPayload);

      HttpURLConnection connection = null;

      LOG.printRequestURL(method, imdsPayload);

      try {
        connection = (HttpURLConnection) url.openConnection();
        /* add additional headers if needed */
        if(headers != null && !headers.isEmpty()) {
          for(Map.Entry<String, String> e : headers.entrySet()) {
            connection.setRequestProperty(e.getKey(), e.getValue());
          }
        }

        /* for POST requests */
        if(method.equals(HttpMethod.POST)) {
          connection.setDoOutput(true);
          try(OutputStream os = connection.getOutputStream()){
            byte[] input = postBody.getBytes(StandardCharsets.UTF_8);
            os.write(input, 0, input.length);
          }
        }

        connection.connect();
        final InputStream stream = connection.getInputStream();
        final BufferedReader reader = new BufferedReader(
            new InputStreamReader(stream, StandardCharsets.UTF_8), 100);
        final String response = reader.lines().collect(Collectors.joining());
        LOG.printHttpResponse(response);
        return response;
      } catch (final Exception exception) {
        responseCode = connection.getResponseCode();
        error = exception.getMessage() != null ? exception.getMessage() : exception.toString();
        if (responseCode == 410 || responseCode == 429 || responseCode == 404
            || (responseCode >= 500 && responseCode <= 599)) {
          int retryTimeoutInMs =
              retrySlots.get(RANDOM.nextInt(retry)) * 1000;
          // Error code 410 indicates IMDS upgrade is in progress, which can take up to 70s
          retryTimeoutInMs = (responseCode == 410
              && retryTimeoutInMs < imdsUpgradeTimeInMs) ?
              imdsUpgradeTimeInMs :
              retryTimeoutInMs;
          retry++;
          if (retry > maxRetry) {
            break;
          } else {
            Thread.sleep(retryTimeoutInMs);
          }
        } else {
          /* if error is not 4xx or 5xx relay the status code as-is to client with IDB message */
          LOG.printStackTrace(ExceptionUtils.getStackTrace(exception));
          final Response.Status status = Response.Status.fromStatusCode(responseCode) != null ? Response.Status.fromStatusCode(responseCode) : Response.Status.FORBIDDEN;
          final Response response = errorResponseWrapper(status, String
              .format(Locale.ROOT, "{ \"error\": \"Couldn't acquire access token from IMDS, cause: %s ,Azure response code: %s\" }",
                  error, responseCode));
          throw new WebApplicationException(response);
        }
      } finally {
        if (connection != null) {
          connection.disconnect();
        }
      }
    }
    /* return 403 for all 4xx */
    if(400 <= responseCode && 499 >= responseCode) {
      final Response response = errorResponseWrapper(Response.Status.FORBIDDEN, String
          .format(Locale.ROOT, "{ \"error\": \"Couldn't acquire access token from IMDS, cause: %s ,Azure response code: %s\" }",
              error, responseCode));
      throw new WebApplicationException(response);
    }
    /* for the rest of errors relay the error code back to client, in case we don't have a proper status code we return 403 */
    final Response.Status status = Response.Status.fromStatusCode(responseCode) != null ? Response.Status.fromStatusCode(responseCode) : Response.Status.FORBIDDEN;
    final Response response = errorResponseWrapper(status, String
        .format(Locale.ROOT, "{ \"error\": \"MSI: Failed to acquire tokens after retrying %s times. Azure response code: %s\" }",
            maxRetry, responseCode));
    throw new WebApplicationException(response);
  }

  /**
   * Helper function that wraps a proper response
   * in case of errors.
   * @return
   */
  protected static Response errorResponseWrapper(final Response.Status status, final String message) {
    return
        Response.serverError().status(status)
            .entity(String.format(Locale.ROOT, message)).build();
  }

  /**
   * Used to send PATH requests using HttpClient.
   * This is method is used because {@link HttpURLConnection}
   * does not support PATH request.
   *
   * @param url      url to send request to
   * @param headers  request headers
   * @param postBody request body
   * @return response
   */
  private String httpPatchRequest(final String url,
      final Map<String, String> headers, final String postBody) {

    try (CloseableHttpClient httpClient = HttpClients.createDefault()) {
      final HttpPatch httpPatch = new HttpPatch(url);
      /* add additional headers if needed */
      if (headers != null && !headers.isEmpty()) {
        for (final Map.Entry<String, String> e : headers.entrySet()) {
          httpPatch.addHeader(e.getKey(), e.getValue());
        }
      }

      final StringEntity payload = new StringEntity(postBody,
          ContentType.APPLICATION_JSON);
      httpPatch.setEntity(payload);

      try (CloseableHttpResponse response = httpClient.execute(httpPatch);
          BufferedReader reader = new BufferedReader(
              new InputStreamReader(response.getEntity().getContent(),
                  StandardCharsets.UTF_8))) {

        final StringBuilder result = new StringBuilder();
        String line;
        while ((line = reader.readLine()) != null) {
          result.append(line);
        }
        int responseCode = response.getStatusLine().getStatusCode();
        if (responseCode != 200) {
          LOG.attachIdentitiesError(responseCode, result.toString());
          final Response.Status status = Response.Status.fromStatusCode(responseCode) != null ? Response.Status.fromStatusCode(responseCode) : Response.Status.FORBIDDEN;
          final Response resp = errorResponseWrapper(status, String
              .format(Locale.ROOT, "{ \"error\": \"Error sending PATCH request to URL %s, reason: %s ,Azure response code: %s \" }",
                  url, result.toString(), responseCode));
          throw new WebApplicationException(resp);
        }
        return result.toString();
      }
    } catch (final Exception e) {
      final Response resp = errorResponseWrapper(Response.Status.FORBIDDEN, String
          .format(Locale.ROOT, "{ \"error\": \"Error sending PATCH request to URL %s, reason: %s \" }",
              url, e.toString()));
      throw new WebApplicationException(resp);
    }
  }
}
