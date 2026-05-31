FROM node:lts-alpine AS web-build

WORKDIR /app

COPY package.json ./
COPY web ./web
RUN npm install
RUN npm run build:css

FROM golang:1.26-alpine AS build

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download
COPY . .
COPY --from=web-build /app/web/static/css/app.css ./web/static/css/app.css
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /out/server ./cmd/server

FROM gcr.io/distroless/static-debian12

COPY --from=build /out/server /server

USER 65532
EXPOSE 8080
ENTRYPOINT ["/server"]
