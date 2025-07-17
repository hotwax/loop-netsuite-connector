#!/bin/bash
#Database Settings
sed -i  's/127.0.0.1:9200/'$ELASTICSEARCH_HOST':9200/g' $CONF_FILE
sed -i -e 's/name="entity_ds_host" value="127.0.0.1"/name="entity_ds_host" value="'$Moqui_DB_HOST'"/g' $CONF_FILE
sed -i -e 's/name="webapp_http_host" value=""/name="webapp_http_host" value="'$Moqui_HOST'"/g' $CONF_FILE
sed -i 's/name="elasticsearch_index_prefix" value="localhost_"/name="elasticsearch_index_prefix" value="'${OFBIZ_INSTANCE_NAME}'_"/g' $CONF_FILE
sed -i 's/name="elasticsearch_user" value=""/name="elasticsearch_user" value="'${ELASTICSEARCH_USER}'_"/g' $CONF_FILE
sed -i 's/name="elasticsearch_password" value=""/name="elasticsearch_password" value="'${ELASTICSEARCH_PASSWORD}'_"/g' $CONF_FILE

sed -i 's/name="entity_ds_user" value="moqui"/name="entity_ds_user" value="'$Moqui_DB_USER'"/g' $CONF_FILE
sed -i 's/name="entity_ds_password" value="moqui"/name="entity_ds_password" value="'$Moqui_DB_PASSWORD'"/g' $CONF_FILE
sed -i 's/name="entity_ds_database" value="moqui"/name="entity_ds_database" value="'$Moqui_DB_NAME'"/g' $CONF_FILE
#sed -i 's/name="entity_ds_database_analytical" value="moqui_analytical"/name="entity_ds_database_analytical" value="'$Moqui_analytical_DB_Name'"/g' $CONF_FILE
#sed -i 's/name="entity_ds_database_configuration" value="moqui_configuration"/name="entity_ds_database_configuration" value="'$Moqui_configuration_DB_Name'"/g' $CONF_FILE

#sed -i -e 's/name="ofbiz_entity_ds_host" value="127.0.0.1"/name="ofbiz_entity_ds_host" value="'$Ofbiz_TRANSACTION_DB_HOST'"/g' $CONF_FILE
#sed -i 's/name="ofbiz_entity_ds_user" value="moqui"/name="ofbiz_entity_ds_user" value="'$Ofbiz_TRANSACTION_DB_USER'"/g' $CONF_FILE
#sed -i 's/name="ofbiz_entity_ds_password" value="moqui"/name="ofbiz_entity_ds_password" value="'$Ofbiz_TRANSACTION_DB_PASSWORD'"/g' $CONF_FILE
#sed -i 's/name="ofbiz_entity_ds_database" value="moqui"/name="ofbiz_entity_ds_database" value="'$Ofbiz_TRANSACTION_DB_NAME'"/g' $CONF_FILE

#sed -i 's/name="ofbiz.instance.name" value="localhost"/name="ofbiz.instance.name" value="'$OFBIZ_INSTANCE_NAME'"/g' $CONF_FILE
#sed -i 's|name="ofbiz.instance.url" value="https://localhost:8443"|name="ofbiz.instance.url" value="'$OFBIZ_INSTANCE_URL'"|g' $CONF_FILE
#
#if [ -n $Moqui_Bi_DB_Host ]; then
#    sed -i 's/name="bi_entity_ds_host" value=""/name="bi_entity_ds_host" value="'$Moqui_Bi_DB_Host'"/g' $CONF_FILE
#    sed -i 's/name="bi_entity_ds_user" value=""/name="bi_entity_ds_user" value="'$Moqui_Bi_DB_User'"/g' $CONF_FILE
#    sed -i 's/name="bi_entity_ds_password" value=""/name="bi_entity_ds_password" value="'$Moqui_Bi_DB_Password'"/g' $CONF_FILE
#    sed -i 's/name="bi_entity_ds_database" value=""/name="bi_entity_ds_database" value="'$Moqui_Bi_DB_Name'"/g' $CONF_FILE
#fi

#Timezone Setting
sed -i 's|name="default_time_zone" value=""|name="default_time_zone" value="'$TIME_ZONE'"|g' $CONF_FILE
sed -i 's|name="database_time_zone" value=""|name="database_time_zone" value="'$TIME_ZONE'"|g' $CONF_FILE

#Control schedule job run setting, default is 60 set to 0 to not run scheduled jobs.
sed -i 's|name="scheduled_job_check_time" value="60"|name="scheduled_job_check_time" value="'$SCHEDULED_JOB_CHECK_TIME'"|g' $CONF_FILE

#if [ -n "$JWT_KEY" ] ; then echo "$JWT_KEY" > "/moqui-framework/runtime/component/maargsetup/conf/jwtKey.txt";fi
#if [ -n "$JWT_KEY" ] ; then echo "$JWT_KEY" > "/moqui-framework/runtime/conf/jwtKey.txt";fi
#if [ -n "$JWT_KEY" ] ; then echo "$JWT_KEY" > "/moqui-deploy/runtime/conf/jwtKey.txt";fi

$SLEEP
screen -dmS Moqui java $JAVA_OPTS -cp . MoquiStart port=8080 conf=$CONF_FILE
tail -F runtime/log/moqui.log