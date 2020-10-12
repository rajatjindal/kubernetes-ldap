FROM golang:1.15 as builder
WORKDIR /go/src/github.com/proofpoint/kubernetes-ldap/

COPY . .
RUN go test ./...
RUN CGO_ENABLED=0 GOOS=linux go build --ldflags "-s -w" -o bin/kubernetes-ldap .

FROM alpine:3.12.0
## use https
RUN sed -i 's/http\:\/\//https\:\/\//g' /etc/apk/repositories
RUN apk add --no-cache ca-certificates
WORKDIR /opt/
COPY --from=builder /go/src/github.com/proofpoint/kubernetes-ldap/bin/kubernetes-ldap .
ENTRYPOINT ["./kubernetes-ldap"]
