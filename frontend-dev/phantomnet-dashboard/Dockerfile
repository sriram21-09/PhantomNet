# Serve pre-built application with Nginx
FROM nginx:alpine

# Copy local build artifacts
COPY dist /usr/share/nginx/html

EXPOSE 80

CMD ["nginx", "-g", "daemon off;"]
