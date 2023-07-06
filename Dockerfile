FROM golang:alpine
#FROM golang:latest

WORKDIR /go/src/app
COPY ./ ./

RUN apk update && apk add git && apk add curl && apk add mysql-client
#RUN go mod init flowers # just first time
#COPY go.mod go.sum ./
RUN go mod download
#RUN go install ariga.io/atlas/cmd/atlas@master

# hot reload library (for dev)
#RUN go get -u github.com/cosmtrek/air
#RUN go get -u github.com/go-delve/delve/cmd/dlv

RUN go build -o /myapp


EXPOSE 8080

# 簡易実行
#CMD ["go", "run", "main.go"]
# 実行
CMD ["/myapp"]
# hot reload
#CMD ["air", "-c", ".air.toml"]
