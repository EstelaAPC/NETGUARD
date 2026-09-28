FROM node:20-alpine AS build
WORKDIR /app
ARG VITE_API_URL=
ENV VITE_API_URL=$VITE_API_URL
COPY package*.json ./
RUN npm ci
COPY . .
RUN npm run build

FROM nginx:1.27-alpine
RUN apk add --no-cache openssl \
  && mkdir -p /etc/nginx/certs \
  && openssl req -x509 -nodes -newkey rsa:2048 -days 3650 \
    -keyout /etc/nginx/certs/netguard-selfsigned.key \
    -out /etc/nginx/certs/netguard-selfsigned.crt \
    -subj "/CN=netguard.local/O=NetGuard MVP"
COPY infra/nginx/default.conf /etc/nginx/conf.d/default.conf
COPY --from=build /app/dist /usr/share/nginx/html
EXPOSE 80 443
