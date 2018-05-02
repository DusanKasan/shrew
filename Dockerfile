FROM golang:latest

WORKDIR /go/src/github.com/DusanKasan/shrew
COPY . .
RUN go build .
CMD ["/go/src/github.com/DusanKasan/shrew/shrew"]