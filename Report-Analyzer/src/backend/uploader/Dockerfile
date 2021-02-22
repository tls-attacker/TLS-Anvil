FROM golang AS build

COPY . /app
WORKDIR /app
RUN CGO_ENABLED=0 GOOS=linux go build -o uploader ./src/cmd/

FROM alpine
COPY --from=build /app/uploader /app/
WORKDIR /upload
VOLUME [ "/upload" ]
ENTRYPOINT [ "/app/uploader", "-path", "/upload" ]