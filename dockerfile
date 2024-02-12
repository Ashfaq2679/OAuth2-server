FROM docker-image-name:latest

COPY build/libs.app.jar /app/app.jar
COPY deploy/start.sh /app
COPY deploy/secrets /app/cers

USER root
RUN yum -y install openssl && yum clean all
RUN chmod -R 777 /app && chown -R 1001:1001 /app

EXPOSE 8090 8080
ENV PATH $PATH:/opt/jre/latest/bin
USER 1000
ENTRYPOINT [ "/app.start.sh" ]
