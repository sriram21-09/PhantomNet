# Serve pre-built application with Nginx
FROM nginxinc/nginx-unprivileged:alpine

# Copy local build artifacts
COPY --chown=nginx:nginx dist /usr/share/nginx/html

EXPOSE 8080

CMD ["nginx", "-g", "daemon off;"]
