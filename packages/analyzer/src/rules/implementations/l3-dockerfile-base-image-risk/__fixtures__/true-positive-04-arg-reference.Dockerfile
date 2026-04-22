# True positive #4 — ARG-referenced base (charter lethal edge case #2)
# An attacker with build-time control can swap the base wholesale.
ARG BASE_IMAGE=ubuntu:22.04
FROM ${BASE_IMAGE}
WORKDIR /opt/mcp
COPY . .
CMD ["./server"]
