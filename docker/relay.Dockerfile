# syntax=docker/dockerfile:1

FROM network_next_base

WORKDIR /app

COPY relay/xdp /app

RUN cc -O2 -DRELAY_USERSPACE -DRELAY_VERSION=\"relay-docker\" -o relay relay.c relay_platform.c relay_base64.c relay_ping_history.c relay_manager.c relay_main.c relay_ping.c relay_config.c relay_userspace.c relay_xdp.c -lsodium -lcurl -lpthread -lm

EXPOSE 40000/udp

CMD [ "/app/relay" ]
