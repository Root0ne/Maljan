import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  /* Enable standalone output for Docker deployment */
  output: "standalone",

  /* Proxy API requests to the FastAPI backend during development */
  async rewrites() {
    return [
      {
        source: "/api/:path*",
        destination: `${process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000"}/api/:path*`,
      },
    ];
  },
};

export default nextConfig;
