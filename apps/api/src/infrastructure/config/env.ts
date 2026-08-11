import dotenv from "dotenv";
import { loadConfig, type Config } from "./config.js";

export function configFromEnv(): Config {
  dotenv.config();
  return loadConfig(process.env);
}
