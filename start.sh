#!/bin/bash

#Set required properties based on infrastructure used e.g. AppDynamics
#AppDynamics properties
APPDYN_OPTS = "-javaagent:/opt/appdyn/javaagent/current/javaagent.jar \
-Dappdynamics.controller.hostName="$APPDYNHOSTNAME" \
-Dappdynamics.controller.port=8181 \
-Dappdynamics.agent.applicationName="$APPDYNAPPNAME" \
-Dappdynamics.agent.tierName="$APP"="$ENV" \
-Dappdynamics.agent.runtime.dir=/tmp"

#Server certs
unset SA_CALL_SECRET
./opt/secretagent/scripts/SecretAgentClient -i DOWNLOAD_CERT -k "$SERVER_ORDER_ID"
if ["$SA_CALL_SUCCESS" = "1"]; then
	echo "Server certificates successfully downloaded"
else
	>$2 echo "ERROR: Unable to download server certificates $SA_CALL_RET_VAL"	
fi

#Decrypt the encrypted password for private key
unset SA_CALL_SECRET
. /opt/secretagent/scripts/SecretAgentClient -i DECRYPT_PRIVATE_PASSWORD -k "$SERVER_ORDER_ID"
if [ "$SA_CALL_SUCCESS" = "1" ]; then
	echo "Password decrypted successfully."
else
	>$2 echo "ERROR: Password decryption failed for server " $SA_CALL_REV_VAL"
	exit 1
fi

SERVER_CERT_PASS=$SA_CALL_SECRET

#Creates keystore and imports then private key for server
export RANDFILE=/tmp/.rnd
openssl rsa -aes256 -in /tmp/cortosis-cert/$cortosis-certs/${SERVER_ORDER_ID}_private.key -out /tmp/servercertimport.key -passin pass:$SERVER_CERT_PASS -passout pass:$SERVER_CERT_PASS
openssl - pkcs12 -export -in /tmp/cortosis-cert/$cortosis-certs/${SERVER_ORDER_ID}_cert.pem -out /app/certs/ssl-server-cert.p12 -certfile /etc/tts-config/"CitiInternalCAChain.pem" -inkey /tmp/servercertimport.key -passin pass:$SERVER_CERT_PASS -passout pass:$SERVER_CERT_PASS

keytool -importkeystore -srckeystore /app/certs/ssl-server-cert.p12 -srcstoretype pkcs12 -srcstorepass $SERVER_CERT_PASS -destkeystore /app/certs/client_keystore.jks -deststorepass $SERVER_CERT_PASS

base64 -d /etc/tts-config/truststore.txt > /appcerts/truststore.jks
TRUSTSTORE_PASS=changeit

java $APPDYN_OPTS -XX:+UnlockExperimentalVMOptions -XX:+UseContainerSupport -XX:InitialRAMPercentage=20.0 -XX:MaxRAMPercentage=70.0 -XXMinRAMPercentage=40.0
-DSECRET_DIR=/tmp/cortosis-certs \
-Dserver.port=9999 \
-Dspring.profiles.active=PROD \
-Dserver.ssl.key-store-password=$SERVER_CERT_PASS \
-Dserver.ssl.trust-store-password=$TRUSTSTORE_PASS \
-Dclient.ssl.key-store-password=$SERVER_CERT_PASS \
-Dclient.ssl.trust-store-password=$TRUSTSTORE_PASS \
-Djavax.security.auth.useSubjectCredsOnly=true \
-Dspring.config.location=/etc/app-config/appconfig.properties \
-Dmanagenent.server.ssl.enabled=false \
-Dmanagement.server.port=8090 \
-jar /app/app.jar