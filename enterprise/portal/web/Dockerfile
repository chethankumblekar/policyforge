# Multi-stage build using Next.js's `output: "standalone"` (see
# next.config.ts) so the runtime image only needs .next/standalone plus
# static assets, not the full node_modules tree.
FROM node:22-alpine AS builder
WORKDIR /src
COPY package.json package-lock.json ./
RUN npm ci
COPY . .
RUN npm run build

FROM node:22-alpine AS runner
WORKDIR /app
ENV NODE_ENV=production
RUN addgroup -S nextjs && adduser -S nextjs -G nextjs
COPY --from=builder /src/public ./public
COPY --from=builder --chown=nextjs:nextjs /src/.next/standalone ./
COPY --from=builder --chown=nextjs:nextjs /src/.next/static ./.next/static
USER nextjs
EXPOSE 3000
ENV PORT=3000
CMD ["node", "server.js"]
