import type { NextConfig } from "next";

const isDev = process.env.NODE_ENV === "development";

const nextConfig: NextConfig = {
  // Static export for production (embedded in Go binary); disabled in dev so rewrites work
  output: isDev ? undefined : "export",
  images: {
    unoptimized: true,
  },
  async rewrites() {
    return [
      {
        source: "/api/:path*",
        destination: "http://localhost:8484/api/:path*",
      },
    ];
  },
};

export default nextConfig;
