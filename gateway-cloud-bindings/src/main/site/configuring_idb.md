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

* Kerberos must be enabled. Most clients don't bother asking for delegation
tokens unless kerberos is enabled.

* You need the URL of your gateway.



## S3A: enabling Delegation


```xml
<property>
  <name>fs.s3a.delegation.token.binding</name>
  <value>org.apache.knox.gateway.cloud.idbroker.s3a.IDBDelegationTokenBinding</value>
</property>
<property>
  <name>fs.s3a.ext.cab.address</name>
  <value>https://ctr-e139-1542663976389-22700-01-000003.hwx.site:8443/gateway/</value>
</property>
```

## GCS: enabling Delegation


```xml
<property>
  <name>fs.gs.delegation.token.binding</name>
  <value>org.apache.knox.gateway.cloud.idbroker.google.CABDelegationTokenBinding</value>
</property>

<property>
  <name>fs.gs.ext.cab.address</name>
  <value>https://ctr-e139-1542663976389-22700-01-000003.hwx.site:8443/gateway/</value>
</property>
<property>
  <name>fs.gs.ext.cab.username</name>
  <value>admin</value>
</property>
<property>
  <name>fs.gs.ext.cab.pass</name>
  <value>admin-password</value>
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
