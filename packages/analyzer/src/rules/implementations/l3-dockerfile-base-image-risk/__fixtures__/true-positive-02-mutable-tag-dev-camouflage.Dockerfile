# True positive #2 — dev-tag camouflage (charter lethal edge case #4)
# The tag "latest-prod" looks pinned but contains the mutable keyword "latest".
FROM python:latest-prod
WORKDIR /srv
COPY . .
CMD ["python", "server.py"]
