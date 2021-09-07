FROM golang:1.16-alpine as build

WORKDIR /app
COPY ./* /app/
RUN go build -o go-cf-auth

FROM alpine as runtime 
COPY --from=build /app/go-cf-auth /
CMD ./go-cf-auth