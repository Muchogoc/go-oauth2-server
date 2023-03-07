# Build Stage
FROM lacion/alpine-golang-buildimage:1.13 AS build-stage

LABEL app="build-go-oauth2-server"
LABEL REPO="https://github.com/Muchogoc/go-oauth2-server"

ENV PROJPATH=/go/src/github.com/Muchogoc/go-oauth2-server

# Because of https://github.com/docker/docker/issues/14914
ENV PATH=$PATH:$GOROOT/bin:$GOPATH/bin

ADD . /go/src/github.com/Muchogoc/go-oauth2-server
WORKDIR /go/src/github.com/Muchogoc/go-oauth2-server

RUN make build-alpine

# Final Stage
FROM lacion/alpine-base-image:latest

ARG GIT_COMMIT
ARG VERSION
LABEL REPO="https://github.com/Muchogoc/go-oauth2-server"
LABEL GIT_COMMIT=$GIT_COMMIT
LABEL VERSION=$VERSION

# Because of https://github.com/docker/docker/issues/14914
ENV PATH=$PATH:/opt/go-oauth2-server/bin

WORKDIR /opt/go-oauth2-server/bin

COPY --from=build-stage /go/src/github.com/Muchogoc/go-oauth2-server/bin/go-oauth2-server /opt/go-oauth2-server/bin/
RUN chmod +x /opt/go-oauth2-server/bin/go-oauth2-server

# Create appuser
RUN adduser -D -g '' go-oauth2-server
USER go-oauth2-server

ENTRYPOINT ["/usr/bin/dumb-init", "--"]

CMD ["/opt/go-oauth2-server/bin/go-oauth2-server"]
