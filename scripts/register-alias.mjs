import fs from "node:fs";
import path from "node:path";
import { registerHooks } from "node:module";
import { pathToFileURL } from "node:url";

const srcRoot = path.resolve(process.cwd(), "src");

function resolveTsFile(candidatePath) {
  if (fs.existsSync(candidatePath) && fs.statSync(candidatePath).isFile()) {
    return candidatePath;
  }
  for (const ext of [".ts", ".tsx", ".mts", ".js", ".mjs"]) {
    const withExt = candidatePath + ext;
    if (fs.existsSync(withExt) && fs.statSync(withExt).isFile()) {
      return withExt;
    }
  }
  for (const indexName of ["index.ts", "index.tsx", "index.js"]) {
    const indexPath = path.join(candidatePath, indexName);
    if (fs.existsSync(indexPath) && fs.statSync(indexPath).isFile()) {
      return indexPath;
    }
  }
  return null;
}

registerHooks({
  resolve(specifier, context, nextResolve) {
    if (specifier === "next/headers") {
      return nextResolve("next/headers.js", context);
    }
    if (specifier.startsWith("@/")) {
      const target = path.join(srcRoot, specifier.slice(2));
      const resolved = resolveTsFile(target);
      if (resolved) {
        return {
          url: pathToFileURL(resolved).href,
          shortCircuit: true,
        };
      }
    }
    if (
      (specifier.startsWith("./") || specifier.startsWith("../")) &&
      context.parentURL?.startsWith("file:")
    ) {
      const parentDir = path.dirname(new URL(context.parentURL).pathname.replace(/^\/([A-Za-z]:)/, "$1"));
      const target = path.resolve(parentDir, specifier);
      const resolved = resolveTsFile(target);
      if (resolved) {
        return {
          url: pathToFileURL(resolved).href,
          shortCircuit: true,
        };
      }
    }
    return nextResolve(specifier, context);
  },
});
