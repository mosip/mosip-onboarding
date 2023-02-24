FROM node:lts-alpine3.17
RUN npm install -g npm@latest newman@latest newman-reporter-htmlextra@latest
RUN apk add curl && \
    curl https://dl.min.io/client/mc/release/linux-amd64/mc -o /bin/mc && \
    chmod +x /bin/mc

ARG container_user=mosip
ARG container_user_group=mosip
ARG container_user_uid=1001
ARG container_user_gid=1001

# Install packages and create user
RUN addgroup -g ${container_user_gid} ${container_user_group} \
&& adduser -u ${container_user_uid} -G ${container_user_group} -s /bin/bash -D ${container_user}

# Permissions
RUN chown -R ${container_user}:${container_user} /home/${container_user}

# Select container user for all tasks
USER ${container_user_uid}:${container_user_gid}

WORKDIR  /home/${container_user}
COPY --chown=${container_user}:${container_user} certs/ ./certs/
COPY *.json ./
COPY *.sh ./

ENV MYDIR=`pwd`
ENV DATE="$(date --utc +%FT%T.%3NZ)"
ENV URL=
ENV CERT_MANAGER=mosip-deployment-client
ENV CERT_MANAGER_PASSWORD=
ENV ENABLE_INSECURE=false
ENV MODULE=

ENV s3-host=
ENV s3-region=
ENV s3-user-key=
ENV s3-user-secret=

ENTRYPOINT ["./entrypoint.sh"]
