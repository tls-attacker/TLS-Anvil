FROM node:12

RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y tcpdump tshark
COPY *.js *.json /app/
WORKDIR /app
RUN npm install

COPY src/ /app/src/
COPY public/ /app/public/

RUN npm run build

ENTRYPOINT [ "node", "/app/dist-backend/index.js" ]