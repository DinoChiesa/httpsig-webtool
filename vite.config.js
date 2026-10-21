import { defineConfig } from "vite";
import { execSync } from "node:child_process";
import pkg from "./package.json" with { type: "json" };

const buildCount = execSync("git rev-list HEAD --count").toString().trim();

export default defineConfig(({ mode }) => {
  const isDev = mode === "development";
  return {
    root: "src",
    base: "./",
    define: {
      BUILD_VERSION: JSON.stringify(`${pkg.version}.${buildCount}`),
    },
    css: {
      preprocessorOptions: {
        scss: { quietDeps: true },
      },
    },
    build: {
      outDir: "../dist",
      emptyOutDir: true,
      sourcemap: isDev,
      minify: !isDev,
      rollupOptions: {
        output: {
          // Stable, unhashed names so propagate.sh and the github.io layout
          // (httpsig/js/main.js, httpsig/css/main.css) keep working.
          entryFileNames: "js/main.js",
          assetFileNames: (assetInfo) =>
            assetInfo.names?.some((n) => n.endsWith(".css"))
              ? "css/main.css"
              : "assets/[name]-[hash][extname]",
        },
      },
    },
  };
});
