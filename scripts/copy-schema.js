import fs from "fs";
import path from "path";

const src = path.join(process.cwd(), "src", "schema.sql");
const dstDir = path.join(process.cwd(), "dist");
const dst = path.join(dstDir, "schema.sql");

if (!fs.existsSync(dstDir)) fs.mkdirSync(dstDir, { recursive: true });
fs.copyFileSync(src, dst);
console.log("Copied schema.sql to dist/");