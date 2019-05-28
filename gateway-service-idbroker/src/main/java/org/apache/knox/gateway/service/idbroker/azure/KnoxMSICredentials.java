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

import com.microsoft.azure.AzureEnvironment;
import com.microsoft.azure.credentials.AzureTokenCredentials;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLEncoder;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.Random;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

/**
 * Get access token for Managed Service Identity. This class is modeled after
 * com.microsoft.azure.credentials.MSICredentials and tailored to return other
 * relevant token information.
 */
public class KnoxMSICredentials extends AzureTokenCredentials {

  private final static String API_VERSION = "2018-02-01";
  private final static String IMDS_ENDPOINT = "169.254.169.254";

  private final List<Integer> retrySlots = new ArrayList<>(Arrays.asList(
      new Integer[] { 1, 1, 2, 3, 5, 8, 13, 21, 34, 55, 89, 144, 233, 377, 610,
          987, 1597, 2584, 4181, 6765 }));
  private final Lock lock = new ReentrantLock();
  private final String resource;

  private int maxRetry = retrySlots.size();
  private String objectId;
  private String clientId;
  private String identityId;

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
    lock.lock();
    /*
     * Here are are not trying the MSI extension installed on the VM
     * but going for the wellknown IMDS endpoint.
     */
    try {
      return getTokenFromIMDSEndpoint(
          tokenAudience == null ? this.resource : tokenAudience);
    } catch (InterruptedException e) {
      throw new RuntimeException(e);
    } finally {
      lock.unlock();
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
      throws IOException, InterruptedException {

    final StringBuilder payload = new StringBuilder();
    try {
      payload.append("api-version");
      payload.append("=");
      payload.append(URLEncoder.encode(API_VERSION, "UTF-8"));
      payload.append("&");
      payload.append("format");
      payload.append("=");
      payload.append("text");
    } catch (IOException exception) {
      throw new RuntimeException(exception);
    }

    return httpRequest(String.format(Locale.ROOT,
        "http://" + IMDS_ENDPOINT + "/metadata/instance/compute/%s?%s",
        resource, payload.toString()));
  }

  /* Get token from well known IMDS endpoint */
  private String getTokenFromIMDSEndpoint(final String tokenAudience)
      throws IOException, InterruptedException {

    final StringBuilder payload = new StringBuilder();

    try {
      payload.append("api-version");
      payload.append("=");
      payload.append(URLEncoder.encode(API_VERSION, "UTF-8"));
      payload.append("&");
      payload.append("resource");
      payload.append("=");
      payload.append(URLEncoder.encode(tokenAudience, "UTF-8"));
      if (this.objectId != null) {
        payload.append("&");
        payload.append("object_id");
        payload.append("=");
        payload.append(URLEncoder.encode(this.objectId, "UTF-8"));
      } else if (this.clientId != null) {
        payload.append("&");
        payload.append("client_id");
        payload.append("=");
        payload.append(URLEncoder.encode(this.clientId, "UTF-8"));
      } else if (this.identityId != null) {
        payload.append("&");
        payload.append("msi_res_id");
        payload.append("=");
        payload.append(URLEncoder.encode(this.identityId, "UTF-8"));
      }
    } catch (IOException exception) {
      throw new RuntimeException(exception);
    }

    return httpRequest(String.format(Locale.ROOT,
        "http://" + IMDS_ENDPOINT + "/metadata/identity/oauth2/token?%s",
        payload.toString()));
  }

  /**
   * Make a HTTP request to IMDS endpoint with a given payload.
   *
   * @param imdsPayload payload
   * @return returns response from IMDS
   * @throws IOException
   * @throws InterruptedException
   */
  private String httpRequest(final String imdsPayload)
      throws IOException, InterruptedException {

    final int imdsUpgradeTimeInMs = 70 * 1000;
    int retry = 1;
    while (retry <= maxRetry) {
      final URL url = new URL(imdsPayload);

      HttpURLConnection connection = null;

      try {
        connection = (HttpURLConnection) url.openConnection();
        connection.setRequestMethod("GET");
        connection.setRequestProperty("Metadata", "true");
        connection.connect();
        final InputStream stream = connection.getInputStream();
        final BufferedReader reader = new BufferedReader(
            new InputStreamReader(stream, "UTF-8"), 100);
        final String result = reader.readLine();
        return result;
        //return adapter.deserialize(result, AzureToken.class);
      } catch (final Exception exception) {
        int responseCode = connection.getResponseCode();
        if (responseCode == 410 || responseCode == 429 || responseCode == 404
            || (responseCode >= 500 && responseCode <= 599)) {
          int retryTimeoutInMs =
              retrySlots.get(new Random().nextInt(retry)) * 1000;
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
          throw new RuntimeException(
              "Couldn't acquire access token from IMDS, verify your objectId, clientId or msiResourceId",
              exception);
        }
      } finally {
        if (connection != null) {
          connection.disconnect();
        }
      }
    }
    //
    if (retry > maxRetry) {
      throw new RuntimeException(String
          .format("MSI: Failed to acquire tokens after retrying %s times",
              maxRetry));
    }
    return null;
  }

}
