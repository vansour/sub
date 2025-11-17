```
services:
  web:
    image: ghcr.io/vansour/v-ui:latest
    container_name: v-ui
    ports:
      - "8080:8080"
    restart: unless-stopped
    volumes:
      - ./config:/app/config
      - ./data:/app/data
```