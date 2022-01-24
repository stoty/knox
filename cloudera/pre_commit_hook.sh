 #!/usr/bin/env bash

set -ex

export MAVEN_OPTS="${MAVEN_OPTS} -Xmx1g -XX:MaxPermSize=256m"

cat > mvn_settings.xml <<EOF
<settings>
<localRepository/>
<mirrors>
    <mirror>
        <id>public</id>
        <mirrorOf>*</mirrorOf>
        <url>https://nexus-private.hortonworks.com/nexus/content/groups/public</url>
    </mirror>
</mirrors>
<profiles/>
</settings>
EOF

echo "::>> cat mvn_settings.xml"
cat mvn_settings.xml

mvn -s mvn_settings.xml --update-snapshots -Dshellcheck=false clean install -Prelease,package,idbroker
