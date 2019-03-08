<!---
  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at
  
   http://www.apache.org/licenses/LICENSE-2.0
  
  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License. See accompanying LICENSE file.
-->

# Configuring IDBroker


## Before you begin

Kerberos must be enabled. Most clients don't bother asking for delegation
tokens unless kerberos is enabled. 
There is some minimal support for authentication with username and password, but
this is primarily for testing.

You need the URL of your Knox gateway.

You need the gateway-client JAR and its dependencies on the classpath of
the machine on which jobs are submitted (i.e. where tokens are requested),
and on those hosts which are executing work.

*Important*: In Jobs which reference a .tar.gz file stored in the cluster filesystem
(including MapReduce and Spark) the relevant JARs must be within that file.
Otherwise: the job may start, but the tokens cannot be unmarshalled at the far
end and the application will not work.


## S3A: enabling Delegation


```xml
<property>
  <name>fs.s3a.delegation.token.binding</name>
  <value>org.apache.knox.gateway.cloud.idbroker.s3a.IDBDelegationTokenBinding</value>
  <description>
  The classname of the IDBroker Delegation Support; this will be loaded by
  the S3A Filesystem connector.
  </description>
</property>
<property>
  <name>fs.s3a.ext.cab.address</name>
  <value>https://ctr-e139-1542663976389-22700-01-000003.hwx.site:8443/gateway/</value>
  <description>
  Address of the gateway.
  </description>
</property>
<property>
  <name>fs.s3a.ext.cab.path</name>
  <value>aws-cab</value>
  <description>
  Sub-path in the gateway to the URL offering the API to request AWS credentials.
  </description>
</property>
<property>
  <name>fs.s3a.ext.cab.dt.path</name>
  <value>dt</value>
  <description>
  Sub-path in the gateway to the URL offering the delegation token login operation.
  </description>
</property>
<property>
  <name>fs.s3a.ext.cab.truststore.location</name>
  <value></value>
  <description>
  Path in the local filesystem where the HTTP trust store can be found.
  </description>
</property>
<property>
  <name>fs.s3a.ext.cab.truststore.pass</name>
  <value></value>
  <description>
  Password to read the trust store
  </description>
</property>
<property>
  <name>fs.s3a.ext.cab.required.group</name>
  <value></value>
  <description>
   fs.(s3a | gs | abfs).ext.cab.required.group - group name.
   this is used to disambiguate the situation where there are multiple
   group mappings and we need to specify which group should be used to
   choose the desired role mapping.
   This will result in the CAB API that specifies the desired group->role
   mapping to be used.
   e.g https://localhost:8443/gateway/aws-cab/cab/api/v1/credentials/group/{groupid}
  </description>
</property>
<property>
  <name>fs.s3a.ext.cab.required.role</name>
  <value></value>
  <description>
    fs.(s3a | gs | abfs).ext.cab.required.role -role id.
    this allows the job submitter to indicate that the specified role
    is required for the job.
    This will result in the CAB API to retrieve credentials for a given role
    to be used.
  </description>
</property>
<property>
  <name>fs.s3a.ext.cab.employ.group.role</name>
  <value>false</value>
  <description>
    Boolean: switch to group role over group roles: {@value}.
    this is interpreted as meaning that the CAB API for acquiring
    credentials for the role mapped to a group even if there is a
    user mapping.
    e.g. https://localhost:8443/gateway/aws-cab/cab/api/v1/credentials/group
  </description>
</property>
<property>
  <name>fs.s3a.ext.cab.employ.user.role</name>
  <value></value>
  <description>
    Boolean: switch to user role over group roles: {@value}.
    this means interrogate user mapping and not check group mappings
    for this job submission.
  </description>
</property>
<property>
  <name>fs.s3a.ext.idbroker.credentials.type</name>
  <value>kerberos</value>
  <description>
  Mechanism to authenticate with the CAB gateway.
  
  Options: 
    kerberos: Kerberos authentication
    username-password: use the values of fs.s3a.ext.cab.username and
                       fs.s3a.ext.cab.pass to authencated.

  Note: if the cluster/client is not configured to authenticate with
  Kerberos (i.e. "hadoop.security.authentication" = "simple", then
  username and password will always be used.
  </description>
</property>
<property>
  <name>fs.s3a.ext.cab.username</name>
  <value>admin</value>
  <description>
  When using username and password authentication, the username to use.
  </description>
</property>
<property>
  <name>fs.s3a.ext.cab.pass</name>
  <value>admin-password</value>
  <description>
  When using username and password authentication, the password to use.
  </description>
</property>
<property>
  <name>fs.s3a.ext.cab.delegation.tokens.include.aws.secrets</name>
  <value>true</value>
  <description>
  Should the S3A Delegation Token include the AWS Secrets?
  For testing token refresh, setting this to false guarantees immediate
  AWS Credential renewal on first use.
  Avoid in production, as it will generate extra load on IDBroker when
  many worker processes are started from a single job. In such a case,
  including the delegation token will, provided the token has not (yet) expired,
  deliver a faster startup.
  </description>
</property>

```

Remember that S3A supports "per-bucket" configuration; when a filesystem
for bucket "BUCKET" is instantiated, all properties with the form
`fs.s3a.bucket.BUCKET.*` are overlaid into the `fs.s3a.*` properties.
All options with the `fs.s3a.ext.` prefix can be configured this way. 

## GCS: enabling Delegation


```xml
<property>
  <name>fs.gs.delegation.token.binding</name>
  <value>org.apache.knox.gateway.cloud.idbroker.google.CABDelegationTokenBinding</value>
  <description>
  The classname of the IDBroker Delegation Support; this will be loaded by
  the GS Filesystem connector.
  </description>
</property>

<property>
  <name>fs.gs.ext.cab.address</name>
  <value>https://ctr-e139-1542663976389-22700-01-000003.hwx.site:8443/gateway/</value>
  <description>
  Address of the gateway.
  </description>
</property>
<property>
  <name>fs.gs.ext.cab.username</name>
  <value>admin</value>
  <description>
  When using username and password authentication, the username to use.
  </description>
</property>
<property>
  <name>fs.gs.ext.cab.pass</name>
  <value>admin-password</value>
  <description>
  When using username and password authentication, the password to use.
  </description>
</property>
```


## Azure ABFS Support

```xml
<property>
  <name>fs.azure.enable.delegation.token</name>
  <value>true</value>
  <description>
  </description>
</property>
<property>
  <name>fs.azure.delegation.token.provider.type</name>
  <value>org.apache.knox.gateway.cloud.idbroker.abfs.AbfsIDBDelegationTokenManager</value>
  <description>
  </description>
</property>
<property>
  <name>fs.azure.account.auth.type</name>
  <value>Custom</value>
</property>
<property>
  <name>fs.azure.account.oauth.provider.type</name>
  <value>org.apache.knox.gateway.cloud.idbroker.abfs.AbfsIDBCredentialProvider</value>
</property>
<property>
  <name></name>
  <value></value>
  <description>
  </description>
</property>
```


## Summary of Configuration Options

In the form for Ambari

```
fs.s3a.delegation.token.binding=org.apache.knox.gateway.cloud.idbroker.s3a.IDBDelegationTokenBinding
fs.s3a.ext.cab.address=https://ctr-e139-1542663976389-22700-01-000003.hwx.site:8443/gateway/
fs.gs.delegation.token.binding=org.apache.knox.gateway.cloud.idbroker.google.CABDelegationTokenBinding
fs.gs.ext.cab.address=https://ctr-e139-1542663976389-22700-01-000003.hwx.site:8443/gateway/
fs.gs.ext.cab.username=admin
fs.gs.ext.cab.pass=admin-password
```


# Spark Configuration

```
spark.hadoop.fs.s3a.ext.cab.address https://ctr-e139-1542663976389-22700-01-000003.hwx.site:8443/gateway/
spark.hadoop.fs.gs.ext.cab.address https://ctr-e139-1542663976389-22700-01-000003.hwx.site:8443/gateway/

spark.hadoop.fs.s3a.delegation.token.binding org.apache.knox.gateway.cloud.idbroker.s3a.IDBDelegationTokenBinding
spark.hadoop.fs.gs.delegation.token.binding org.apache.knox.gateway.cloud.idbroker.google.CABDelegationTokenBinding

spark.yarn.access.hadoopFileSystems s3a://landsat-pds/,gs://something/

```

## Troubleshooting


### Server-side Logs


The audit log is on the server in

`/usr/hdp/current/knox-server/logs/gateway-audit.log`

### Verifying that Store credentials have been set in Knox

The `knoxcli.sh` command line can be used to verify that aliases have been
set. For example, for the `aws-cab` binding: 

```bash
cd  /usr/hdp/current/knox-server/bin/
./knoxcli.sh list-alias --cluster aws-cab
```
 


### `Unable to obtain Principal Name for authentication`

The User is not actually logged in with Kerberos. 

```
Caused by: org.apache.knox.gateway.shell.KnoxShellException:
 javax.security.auth.login.LoginException:
  Unable to obtain Principal Name for authentication 
    at org.apache.knox.gateway.shell.KnoxSession.executeNow(KnoxSession.java:469)
    at org.apache.knox.gateway.shell.AbstractRequest.execute(AbstractRequest.java:50)
    at org.apache.knox.gateway.shell.knox.token.Get$Request.lambda$callable$0(Get.java:66)
    at org.apache.knox.gateway.shell.AbstractRequest.now(AbstractRequest.java:83)
    at org.apache.knox.gateway.cloud.idbroker.IDBClient.requestKnoxDelegationToken(IDBClient.java:420)
    ... 22 more
Caused by: javax.security.auth.login.LoginException: Unable to obtain Principal Name for authentication 
    at com.sun.security.auth.module.Krb5LoginModule.promptForName(Krb5LoginModule.java:841)
    at com.sun.security.auth.module.Krb5LoginModule.attemptAuthentication(Krb5LoginModule.java:704)
    at com.sun.security.auth.module.Krb5LoginModule.login(Krb5LoginModule.java:617)
    at sun.reflect.NativeMethodAccessorImpl.invoke0(Native Method)
```


### `unable to find valid certification path to requested target`

There's no certificate in the configured path.

The default path is `~/gateway-client-trust.jks`

```
Caused by: org.apache.knox.gateway.shell.KnoxShellException:
 javax.net.ssl.SSLHandshakeException: sun.security.validator.ValidatorException:
 PKIX path building failed: sun.security.provider.certpath.SunCertPathBuilderException:
  unable to find valid certification path to requested target
  at org.apache.knox.gateway.shell.KnoxSession.lambda$executeNow$0(KnoxSession.java:464)
  at java.security.AccessController.doPrivileged(Native Method)
  at javax.security.auth.Subject.doAs(Subject.java:360)
  at org.apache.knox.gateway.shell.KnoxSession.executeNow(KnoxSession.java:452)
  at org.apache.knox.gateway.shell.AbstractRequest.execute(AbstractRequest.java:50)
  at org.apache.knox.gateway.shell.knox.token.Get$Request.lambda$callable$0(Get.java:66)
  at org.apache.knox.gateway.shell.AbstractRequest.now(AbstractRequest.java:83)
  at org.apache.knox.gateway.cloud.idbroker.IDBClient.requestKnoxDelegationToken(IDBClient.java:420)
  ... 24 more
Caused by: javax.net.ssl.SSLHandshakeException: sun.security.validator.ValidatorException: PKIX path building failed: sun.security.provider.certpath.SunCertPathBuilderException: unable to find valid certification path to requested target
  at sun.security.ssl.Alerts.getSSLException(Alerts.java:192)
  at sun.security.ssl.SSLSocketImpl.fatal(SSLSocketImpl.java:1949)
  at sun.security.ssl.Handshaker.fatalSE(Handshaker.java:302)
  at sun.security.ssl.Handshaker.fatalSE(Handshaker.java:296)
  at sun.security.ssl.ClientHandshaker.serverCertificate(ClientHandshaker.java:1514)
  at sun.security.ssl.ClientHandshaker.processMessage(ClientHandshaker.java:216)
  at sun.security.ssl.Handshaker.processLoop(Handshaker.java:1026)
  at sun.security.ssl.Handshaker.process_record(Handshaker.java:961)
  at sun.security.ssl.SSLSocketImpl.readRecord(SSLSocketImpl.java:1062)
  at sun.security.ssl.SSLSocketImpl.performInitialHandshake(SSLSocketImpl.java:1375)
  at sun.security.ssl.SSLSocketImpl.startHandshake(SSLSocketImpl.java:1403)
  at sun.security.ssl.SSLSocketImpl.startHandshake(SSLSocketImpl.java:1387)
  at org.apache.http.conn.ssl.SSLConnectionSocketFactory.createLayeredSocket(SSLConnectionSocketFactory.java:396)
  at org.apache.http.conn.ssl.SSLConnectionSocketFactory.connectSocket(SSLConnectionSocketFactory.java:355)
  at org.apache.http.impl.conn.DefaultHttpClientConnectionOperator.connect(DefaultHttpClientConnectionOperator.java:142)
  at org.apache.http.impl.conn.PoolingHttpClientConnectionManager.connect(PoolingHttpClientConnectionManager.java:373)
  at org.apache.http.impl.execchain.MainClientExec.establishRoute(MainClientExec.java:394)
  at org.apache.http.impl.execchain.MainClientExec.execute(MainClientExec.java:237)
  at org.apache.http.impl.execchain.ProtocolExec.execute(ProtocolExec.java:185)
  at org.apache.http.impl.execchain.RetryExec.execute(RetryExec.java:89)
  at org.apache.http.impl.execchain.RedirectExec.execute(RedirectExec.java:110)
  at org.apache.http.impl.client.InternalHttpClient.doExecute(InternalHttpClient.java:185)
  at org.apache.http.impl.client.CloseableHttpClient.execute(CloseableHttpClient.java:72)
  at org.apache.knox.gateway.shell.KnoxSession.lambda$executeNow$0(KnoxSession.java:456)
  ... 31 more
Caused by: sun.security.validator.ValidatorException: PKIX path building failed: sun.security.provider.certpath.SunCertPathBuilderException: unable to find valid certification path to requested target
  at sun.security.validator.PKIXValidator.doBuild(PKIXValidator.java:387)
  at sun.security.validator.PKIXValidator.engineValidate(PKIXValidator.java:292)
  at sun.security.validator.Validator.validate(Validator.java:260)
  at sun.security.ssl.X509TrustManagerImpl.validate(X509TrustManagerImpl.java:324)
  at sun.security.ssl.X509TrustManagerImpl.checkTrusted(X509TrustManagerImpl.java:229)
  at sun.security.ssl.X509TrustManagerImpl.checkServerTrusted(X509TrustManagerImpl.java:124)
  at sun.security.ssl.ClientHandshaker.serverCertificate(ClientHandshaker.java:1496)
  ... 50 more
Caused by: sun.security.provider.certpath.SunCertPathBuilderException: unable to find valid certification path to requested target
  at sun.security.provider.certpath.SunCertPathBuilder.build(SunCertPathBuilder.java:141)
  at sun.security.provider.certpath.SunCertPathBuilder.engineBuild(SunCertPathBuilder.java:126)
  at java.security.cert.CertPathBuilder.build(CertPathBuilder.java:280)
  at sun.security.validator.PKIXValidator.doBuild(PKIXValidator.java:382)

```

### `AccessDeniedException` ... `Error 401` against the IDB token URL (`gateway/dt/knoxtoken/api/v1/token`)

The client unauthorized. Possible causes.

1. The client is configured to use basic authentication, rather than kerberos,
but the Knox server requires Kerberos.
1. The client is using Kerberos, but their kerberos ticket has expired.

### Internal Service error 401 or 403 on AWS CAB

This happens after the initial IDBroker Authentication Token has been issued. 

1. CAB topology does not have the AWS Credentials set for the specific user.
1. The Kerberos user is simply unknown to the endpoint.
1. The ARN of the role to issue tokens for is wrong or the IAM account defined
in the access key does not have the permission to assume that role.

The latter can be checked in the server logs; look for text such as

```
2019-01-24 15:15:44,976 ERROR idbroker.aws (KnoxAWSClient.java:getAssumeRoleResult(146))
- Cloud Access Broker is not permitted to assume the specified role arn:aws:iam::11111111:role/s3
: Access denied (Service: AWSSecurityTokenService; Status Code: 403;
 Error Code: AccessDenied; Request ID: ebbbc35d-1fea-11e9-b132-3dc6e815b898)
```


### `HTTP/1.1 500 Internal Server Error` in `fetchAWSCredentials`

This can happen if the AWS CAB is not configured with any AWS credentials.

```
Error org.apache.knox.gateway.shell.KnoxShellException:
 org.apache.knox.gateway.shell.ErrorResponse:
  https://ctr-e139-1542663976389-57507-01-000003.hwx.site:8443/gateway/aws-cab/cab/api/v1/credentials:
   HTTP/1.1 500 Internal Server Error
  at org.apache.knox.gateway.shell.AbstractRequest.now(AbstractRequest.java:87)
  at org.apache.knox.gateway.cloud.idbroker.IDBClient.fetchAWSCredentials(IDBClient.java:360)
  at org.apache.knox.gateway.cloud.idbroker.s3a.IDBDelegationTokenBinding.fetchMarshalledAWSCredentials(IDBDelegationTokenBinding.java:199)
```

### `Unable to obtain Principal Name for authentication`

You are not logged in with Kerberos.

```
org.apache.knox.gateway.shell.KnoxShellException: javax.security.auth.login.LoginException: Unable to obtain Principal Name for authentication 
  at org.apache.knox.gateway.shell.KnoxSession.executeNow(KnoxSession.java:477)
  at org.apache.knox.gateway.shell.AbstractRequest.execute(AbstractRequest.java:50)
  at org.apache.knox.gateway.shell.knox.token.Get$Request.lambda$callable$0(Get.java:66)
  at org.apache.knox.gateway.shell.AbstractRequest.now(AbstractRequest.java:83)
  at org.apache.knox.gateway.cloud.idbroker.IDBClient.requestKnoxDelegationToken(IDBClient.java:430)
  ... 31 more
Caused by: javax.security.auth.login.LoginException: Unable to obtain Principal Name for authentication 
  at com.sun.security.auth.module.Krb5LoginModule.promptForName(Krb5LoginModule.java:841)
  at com.sun.security.auth.module.Krb5LoginModule.attemptAuthentication(Krb5LoginModule.java:704)
  at com.sun.security.auth.module.Krb5LoginModule.login(Krb5LoginModule.java:617)
  at sun.reflect.NativeMethodAccessorImpl.invoke0(Native Method)
  at sun.reflect.NativeMethodAccessorImpl.invoke(NativeMethodAccessorImpl.java:62)
  at sun.reflect.DelegatingMethodAccessorImpl.invoke(DelegatingMethodAccessorImpl.java:43)
  at java.lang.reflect.Method.invoke(Method.java:498)
  at javax.security.auth.login.LoginContext.invoke(LoginContext.java:755)
  at javax.security.auth.login.LoginContext.access$000(LoginContext.java:195)
  at javax.security.auth.login.LoginContext$4.run(LoginContext.java:682)
  at javax.security.auth.login.LoginContext$4.run(LoginContext.java:680)
  at java.security.AccessController.doPrivileged(Native Method)
  at javax.security.auth.login.LoginContext.invokePriv(LoginContext.java:680)
  at javax.security.auth.login.LoginContext.login(LoginContext.java:587)
  at org.apache.knox.gateway.shell.KnoxSession.executeNow(KnoxSession.java:459)
```


###  `HTTP/1.1 400 Bad request: token has expired`

The IDBroker token has expired and so requests for tokens from an object store
are rejected.

```
org.apache.knox.gateway.shell.KnoxShellException: org.apache.knox.gateway.shell.ErrorResponse: 
  https://knox.example.org:8443/gateway/aws-cab/cab/api/v1/credentials: HTTP/1.1 400 Bad request: token has expired
  at org.apache.knox.gateway.shell.AbstractRequest.now(AbstractRequest.java:87)
  at org.apache.knox.gateway.cloud.idbroker.IDBClient.fetchAWSCredentials(IDBClient.java:493)
  at org.apache.knox.gateway.cloud.idbroker.s3a.IDBDelegationTokenBinding.fetchMarshalledAWSCredentials(IDBDelegationTokenBinding.java:207)
  at org.apache.knox.gateway.cloud.idbroker.s3a.IDBDelegationTokenBinding.updateAWSCredentials(IDBDelegationTokenBinding.java:526)
  at org.apache.knox.gateway.cloud.idbroker.s3a.IDBDelegationTokenBinding.collectAWSCredentials(IDBDelegationTokenBinding.java:513)
  at org.apache.knox.gateway.cloud.idbroker.s3a.IDBDelegationTokenBinding.access$100(IDBDelegationTokenBinding.java:87)
  at org.apache.knox.gateway.cloud.idbroker.s3a.IDBDelegationTokenBinding$IDBCredentials.fetchCredentials(IDBDelegationTokenBinding.java:630)
  at org.apache.knox.gateway.cloud.idbroker.s3a.IDBDelegationTokenBinding$IDBCredentials.getCredentials(IDBDelegationTokenBinding.java:615)
  at org.apache.hadoop.fs.s3a.AWSCredentialProviderList.getCredentials(AWSCredentialProviderList.java:177)
  at com.amazonaws.http.AmazonHttpClient$RequestExecutor.getCredentialsFromContext(AmazonHttpClient.java:1166)
```

Possible causes: 

* there is a bug in the IDBroker code related to checking the expiry of tokens
* the clock of the local system is significantly out of sync with the remote service.
* the configured timezone of the local system or that of the remote service is incorrect.

### `NoAuthWithAWSException: Knox token has expired`

```
java.nio.file.AccessDeniedException: example-bucket 
  org.apache.hadoop.fs.s3a.auth.NoAuthWithAWSException:
  Knox token has expired; the current token is Knox S3A Delegation Token issued=2019-03-15T15:14:39.139Z, expiry=2019-03-15T16:14:39Z, 
  endpoint=https://knox.example.org:8443/gateway/aws-cab
  Created from https://knox.example.org:8443/gateway/aws-cab
  at org.apache.hadoop.fs.s3a.S3AUtils.translateException(S3AUtils.java:200)
  at org.apache.hadoop.fs.s3a.Invoker.once(Invoker.java:111)
  at org.apache.hadoop.fs.s3a.Invoker.lambda$retry$3(Invoker.java:265)
  at org.apache.hadoop.fs.s3a.Invoker.retryUntranslated(Invoker.java:322)
  at org.apache.hadoop.fs.s3a.Invoker.retry(Invoker.java:261)
  at org.apache.hadoop.fs.s3a.Invoker.retry(Invoker.java:236)
  at org.apache.hadoop.fs.s3a.S3AFileSystem.verifyBucketExists(S3AFileSystem.java:423)
  at org.apache.hadoop.fs.s3a.S3AFileSystem.initialize(S3AFileSystem.java:357)
  at org.apache.hadoop.fs.FileSystem.createFileSystem(FileSystem.java:3366)
  at org.apache.hadoop.fs.FileSystem.access$200(FileSystem.java:136)
  at org.apache.hadoop.fs.FileSystem$Cache.getInternal(FileSystem.java:3415)
  at org.apache.hadoop.fs.FileSystem$Cache.get(FileSystem.java:3383)
  at org.apache.hadoop.fs.FileSystem.get(FileSystem.java:489)
  at org.apache.hadoop.fs.Path.getFileSystem(Path.java:361)
  at org.apache.hadoop.fs.store.diag.StoreDiag.executeFileSystemOperations(StoreDiag.java:844)
  at org.apache.hadoop.fs.store.diag.StoreDiag.run(StoreDiag.java:426)
  at org.apache.hadoop.fs.store.diag.StoreDiag.run(StoreDiag.java:366)
  at org.apache.hadoop.util.ToolRunner.run(ToolRunner.java:76)
  at org.apache.hadoop.util.ToolRunner.run(ToolRunner.java:90)
  at org.apache.hadoop.fs.store.diag.StoreDiag.exec(StoreDiag.java:1157)
  at org.apache.hadoop.fs.store.diag.StoreDiag.main(StoreDiag.java:1166)
  at storediag.main(storediag.java:24)
  at sun.reflect.NativeMethodAccessorImpl.invoke0(Native Method)
  at sun.reflect.NativeMethodAccessorImpl.invoke(NativeMethodAccessorImpl.java:62)
  at sun.reflect.DelegatingMethodAccessorImpl.invoke(DelegatingMethodAccessorImpl.java:43)
  at java.lang.reflect.Method.invoke(Method.java:498)
  at org.apache.hadoop.util.RunJar.run(RunJar.java:318)
  at org.apache.hadoop.util.RunJar.main(RunJar.java:232)
```

The Knox token has expired, and so cannot be used to request new cloud provider credentials.
