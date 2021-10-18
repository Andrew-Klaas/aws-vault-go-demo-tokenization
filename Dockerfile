# Start from a Debian image with the latest version of Go installed
# and a workspace (GOPATH) configured at /go.
FROM golang
ADD . /go/src/github.com/Andrew-Klaas/aws-vault-go-demo-tokenization
WORKDIR /go/src/github.com/Andrew-Klaas/aws-vault-go-demo-tokenization
RUN go get github.com/Andrew-Klaas/aws-vault-go-demo-tokenization
RUN go get github.com/hashicorp/hcl/hcl/ast
RUN go get github.com/cenkalti/backoff/v3
RUN go get github.com/hashicorp/vault/api
RUN go get github.com/lib/pq
RUN go install /go/src/github.com/Andrew-Klaas/aws-vault-go-demo-tokenization


# Run the outyet command by default when the container starts.
ENTRYPOINT /go/bin/aws-vault-go-demo-tokenization

# Document that the service listens on port 8080.
EXPOSE 9090

#docker build -t aklaas2/aws-vault-go-demo-tokenization .;docker push aklaas2/aws-vault-go-demo-tokenization:latest
