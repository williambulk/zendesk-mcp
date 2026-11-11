import { redactSecrets } from "./security.js";

export type LogLevel = "debug" | "info" | "warn" | "error" | "silent";

const LEVEL_PRIORITY: Record<LogLevel, number> = {
  debug: 10,
  info: 20,
  warn: 30,
  error: 40,
  silent: 100,
};

export interface LoggerOptions {
  level?: LogLevel;
  knownSecrets?: () => readonly (string | undefined)[];
  sink?: (line: string) => void;
}

export class SafeLogger {
  private readonly minPriority: number;
  private readonly knownSecrets?: () => readonly (string | undefined)[];
  private readonly sink: (line: string) => void;

  constructor(options?: LoggerOptions) {
    const level = options?.level ?? "info";
    this.minPriority = LEVEL_PRIORITY[level] ?? LEVEL_PRIORITY.info;
    this.knownSecrets = options?.knownSecrets;
    this.sink =
      options?.sink ??
      ((line: string) => {
        process.stderr.write(`${line}\n`);
      });
  }

  public debug(message: string, meta?: Record<string, unknown>): void {
    this.log("debug", message, meta);
  }

  public info(message: string, meta?: Record<string, unknown>): void {
    this.log("info", message, meta);
  }

  public warn(message: string, meta?: Record<string, unknown>): void {
    this.log("warn", message, meta);
  }

  public error(message: string, meta?: Record<string, unknown>): void {
    this.log("error", message, meta);
  }

  private log(
    level: Exclude<LogLevel, "silent">,
    message: string,
    meta?: Record<string, unknown>
  ): void {
    if (LEVEL_PRIORITY[level] < this.minPriority) {
      return;
    }
    const secrets = this.knownSecrets ? this.knownSecrets() : [];
    const timestamp = new Date().toISOString();
    const serializedMeta = meta ? ` ${JSON.stringify(meta)}` : "";
    const rawLine = `[${timestamp}] [zendesk-mcp] [${level.toUpperCase()}] ${message}${serializedMeta}`;
    const safeLine = redactSecrets(rawLine, secrets);
    this.sink(safeLine);
  }
}
