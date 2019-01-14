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
