FROM node:12-alpine3.12
ARG REST_API_BASE_URL=http://localhost:5000/api/v1
ENV REST_API_BASE_URL ${REST_API_BASE_URL}

RUN apk update && apk add tshark tcpdump
COPY *.js *.json /app/
WORKDIR /app
RUN npm install

COPY src/ /app/src/
COPY public/ /app/public/

RUN npm run build

ENTRYPOINT [ "node", "/app/dist-backend/backend/index.js" ]
