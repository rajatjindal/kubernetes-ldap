FROM golang:1.8.0
WORKDIR /go/src/github.com/apprenda-kismatic/kubernetes-ldap/

COPY . .
RUN make

WORKDIR /opt/
RUN cp /go/src/github.com/apprenda-kismatic/kubernetes-ldap/bin/kubernetes-ldap .
RUN rm -rf /go
ENTRYPOINT ["./kubernetes-ldap"]
