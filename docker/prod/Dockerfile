FROM public.ecr.aws/j6s7y7u4/hotwax/ubuntu:22.04
RUN update-java-alternatives -s java-1.11.0-openjdk-amd64 

# Setup JAVA_HOME -- useful for docker commandline
ENV JAVA_HOME=/usr/lib/jvm/java-11-openjdk-amd64
ENV PATH="$JAVA_HOME/bin:$PATH"
# Clone the necessary repositories in one RUN command to reduce image layers
WORKDIR /
RUN git clone --depth 1 -b "v3.4.0" https://github.com/hotwax/moqui-framework.git
WORKDIR /moqui-framework
RUN git clone --depth 1 -b "v3.2.0" https://github.com/hotwax/moqui-runtime.git runtime
WORKDIR /moqui-framework/runtime/component
RUN git clone --depth 1 -b "v1.1.0" https://github.com/hotwax/loop-netsuite-connector.git

WORKDIR /moqui-framework

RUN echo "org.gradle.daemon=false" | tee -a gradle.properties

# Copy configuration files
RUN cp runtime/component/loop-netsuite-connector/docker/MoquiProductionConf.xml runtime/conf/

# Create WAR file and extract it
RUN ./gradlew addRuntime
RUN mkdir -p /moqui-deploy && \
    cd /moqui-deploy && \
    jar -xvf /moqui-framework/moqui-plus-runtime.war

# Set environment variables
ENV DB_LOAD="./gradlew loadProduction -Ptypes=seed,seed-initial,install,ext-seed,ext -Praw"
ENV JAVA_OPTS="-Xms4096m -Xmx4096m"
ENV CONF_FILE="/moqui-framework/runtime/conf/MoquiProductionConf.xml"
ENV SLEEP="sleep 2"

ENV Moqui_HOST=""
ENV Moqui_DB_HOST=""
ENV Moqui_DB_USER=""
ENV Moqui_DB_PASSWORD=""
ENV Moqui_DB_NAME=""

ENV ELASTICSEARCH_HOST=""
ENV ELASTICSEARCH_USER=""
ENV ELASTICSEARCH_PASSWORD=""
ENV TIME_ZONE=""
ENV SCHEDULED_JOB_CHECK_TIME="60"

WORKDIR /moqui-deploy
# Copy entrypoint script and set executable permissions
COPY docker/prod/entrypoint.sh .
RUN chmod +x entrypoint.sh

# Expose the application port
EXPOSE 8080

# Define the entrypoint
ENTRYPOINT ["./entrypoint.sh", "&&", "bash"]