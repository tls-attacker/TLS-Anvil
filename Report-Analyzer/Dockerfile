FROM node:12-alpine3.12

RUN apk update && apk add tshark tcpdump
COPY *.js *.json /app/
WORKDIR /app
RUN npm install

COPY src/ /app/src/
COPY public/ /app/public/

RUN npm run build

ENTRYPOINT [ "node", "/app/dist-backend/index.js" ]