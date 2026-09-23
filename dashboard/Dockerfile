FROM nginx:alpine-slim

LABEL org.opencontainers.image.title="AgentGate Dashboard" \
      org.opencontainers.image.description="Standalone detached web control plane and AI policy architect for AgentGate" \
      org.opencontainers.image.source="https://github.com/lawrencemwangi496-design/agentgate" \
      org.opencontainers.image.licenses="MIT"

# Remove default nginx config and web root
RUN rm -rf /etc/nginx/conf.d/default.conf /usr/share/nginx/html/*

# Copy custom nginx configuration
COPY nginx.conf /etc/nginx/conf.d/default.conf

# Copy static assets (HTML, CSS, JS)
COPY index.html /usr/share/nginx/html/
COPY css/ /usr/share/nginx/html/css/
COPY js/ /usr/share/nginx/html/js/

EXPOSE 3000

HEALTHCHECK --interval=30s --timeout=3s --retries=3 \
  CMD wget --no-verbose --tries=1 --spider http://127.0.0.1:3000/healthz || exit 1

CMD ["nginx", "-g", "daemon off;"]
