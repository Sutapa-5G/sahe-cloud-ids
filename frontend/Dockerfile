FROM node:22-slim AS build
WORKDIR /app
COPY frontend/package*.json ./
RUN npm install
COPY frontend/ ./
ARG VITE_API_BASE_URL=http://localhost:8000
ENV VITE_API_BASE_URL=$VITE_API_BASE_URL
RUN npm run build

FROM nginx:alpine
COPY --from=build /app/dist /usr/share/nginx/html
# React Router uses client-side routing — nginx must fall back to
# index.html for any path it doesn't recognize as a static file,
# otherwise refreshing a page like /firewall gives a 404.
COPY frontend/nginx.conf /etc/nginx/conf.d/default.conf
EXPOSE 80
