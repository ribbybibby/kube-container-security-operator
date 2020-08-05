FROM golang:1.14-alpine AS build
WORKDIR /go/src/github.com/ribbybibby/kube-container-security-operator
COPY . /go/src/github.com/ribbybibby/kube-container-security-operator
ENV CGO_ENABLED 0
RUN apk --no-cache add git make &&\
  make

FROM alpine:3.12
ENV TRIVY_VERSION 0.10.1
RUN apk --no-cache add tini &&\
  wget -O - https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz |\
  tar xz -C /usr/local/bin/
COPY --from=build /kube-container-security-operator /kube-container-security-operator

ENTRYPOINT ["/sbin/tini", "--"]
CMD [ "/kube-container-security-operator" ]
