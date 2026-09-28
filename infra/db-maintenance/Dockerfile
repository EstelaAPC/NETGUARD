FROM postgres:16-alpine

COPY initdb/ /sql/
COPY db-maintenance/ /scripts/

RUN chmod +x /scripts/apply-loop-risk.sh
