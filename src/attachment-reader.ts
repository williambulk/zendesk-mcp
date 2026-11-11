import { PolicyViolationError, ZendeskApiError } from "./errors.js";
import { getTenantOrigin, stripHtmlToText } from "./security.js";

export const MAX_ATTACHMENT_BYTES = 10 * 1024 * 1024;

/** Only Zendesk-controlled storage locations are eligible; URLs never come from tool arguments. */
export function validateAttachmentDownloadUrl(input: string | URL, subdomain: string) {
  const url = new URL(input);
  const tenant = new URL(getTenantOrigin(subdomain));
  if (url.protocol !== "https:" || url.username || url.password || url.port) {
    throw new PolicyViolationError("UNSAFE_ATTACHMENT_URL", "Attachment downloads require HTTPS without embedded credentials or custom ports.");
  }
  const sameTenant = url.origin === tenant.origin;
  const storage = /^[a-z0-9-]+\.zdusercontent\.com$/.test(url.hostname) || url.hostname === "production-zendesk-attachments.s3.amazonaws.com";
  if ((!sameTenant && !storage) || (sameTenant && !url.pathname.startsWith("/attachments/"))) {
    throw new PolicyViolationError("EXTERNAL_ATTACHMENT_HOST", "Attachment points outside supported Zendesk attachment storage. Download refused; no credentials were sent to that host.");
  }
  return { url, sameTenant };
}

export async function downloadAttachment(options: {
  url: string; subdomain: string; accessToken: string; timeoutMs: number; fetchFn: typeof fetch;
}) {
  let target = validateAttachmentDownloadUrl(options.url, options.subdomain);
  let sendAuth = target.sameTenant;
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), options.timeoutMs);
  try {
    for (let redirects = 0; redirects <= 4; redirects++) {
      const response = await options.fetchFn(target.url.toString(), {
        method: "GET", redirect: "manual", signal: controller.signal, credentials: "omit",
        headers: sendAuth && target.sameTenant ? { Authorization: `Bearer ${options.accessToken}` } : {},
      });
      if ([301, 302, 303, 307, 308].includes(response.status)) {
        await response.body?.cancel();
        const location = response.headers.get("location");
        if (!location || redirects === 4) throw new PolicyViolationError("ATTACHMENT_REDIRECT_LIMIT", "Attachment redirect chain is invalid or too long.");
        target = validateAttachmentDownloadUrl(new URL(location, target.url), options.subdomain);
        sendAuth = sendAuth && target.sameTenant;
        continue;
      }
      if (!response.ok) { await response.body?.cancel(); throw new ZendeskApiError(response.status, `Attachment download returned HTTP ${response.status}.`); }
      const declaredLength = Number(response.headers.get("content-length"));
      if (declaredLength > MAX_ATTACHMENT_BYTES) {
        await response.body?.cancel();
        throw new PolicyViolationError("ATTACHMENT_TOO_LARGE", "Attachment exceeds the 10 MiB download limit.");
      }
      if (!response.body) throw new ZendeskApiError(502, "Attachment download returned no body.");
      const reader = response.body.getReader();
      const chunks: Uint8Array[] = [];
      let size = 0;
      try {
        while (true) {
          const part = await reader.read();
          if (part.done) break;
          size += part.value.byteLength;
          if (size > MAX_ATTACHMENT_BYTES) {
            await reader.cancel();
            throw new PolicyViolationError("ATTACHMENT_TOO_LARGE", "Attachment exceeds the 10 MiB download limit.");
          }
          chunks.push(part.value);
        }
      } finally { reader.releaseLock(); }
      return { bytes: Buffer.concat(chunks, size), contentType: (response.headers.get("content-type") ?? "application/octet-stream").split(";")[0].trim().toLowerCase() };
    }
    throw new Error("Unreachable");
  } catch (err) {
    if (err instanceof PolicyViolationError || err instanceof ZendeskApiError) throw err;
    // Network errors may contain signed URLs. Do not expose them in diagnostics.
    throw new ZendeskApiError(0, "Attachment download failed or timed out.");
  } finally { clearTimeout(timeout); }
}

export function attachmentImageMime(bytes: Buffer): string | null {
  if (bytes.subarray(0, 8).equals(Buffer.from([137,80,78,71,13,10,26,10]))) return "image/png";
  if (bytes[0] === 255 && bytes[1] === 216 && bytes[2] === 255) return "image/jpeg";
  if (/^GIF8[79]a$/.test(bytes.subarray(0, 6).toString("ascii"))) return "image/gif";
  if (bytes.subarray(0, 4).toString() === "RIFF" && bytes.subarray(8, 12).toString() === "WEBP") return "image/webp";
  return null;
}

export function attachmentText(bytes: Buffer, mime: string, maxChars: number) {
  if (!(mime.startsWith("text/") || ["application/json", "application/xml", "application/csv"].includes(mime))) return null;
  let text: string;
  try { text = new TextDecoder("utf-8", { fatal: true }).decode(bytes); }
  catch { return null; }
  if (mime === "text/html" || mime === "application/xhtml+xml") text = stripHtmlToText(text);
  return { text: text.slice(0, maxChars), truncated: text.length > maxChars };
}
