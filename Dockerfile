FROM node:9

RUN mkdir /app
WORKDIR /app

COPY package.json .
COPY yarn.lock .
RUN yarn --production

COPY . .

ENV UPDATE_INTERVAL 300
CMD [ "./build/poll-ip" ]
