import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  experimental: {
    turbopack: {
      // @ts-expect-error - rootDir is not in the type definition
      rootDir: __dirname,
    },
  },
};

export default nextConfig;
