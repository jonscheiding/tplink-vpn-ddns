FROM node:9

RUN mkdir /app
WORKDIR /app

COPY . .
RUN yarn --production

ENV UPDATE_INTERVAL 300
CMD [ "./build/poll-ip" ]
