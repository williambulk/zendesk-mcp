import fs from "node:fs/promises";
import path from "node:path";
import { ZendeskMcpConfig } from "./config.js";
import { ZendeskApiClient } from "./zendesk-client.js";

interface WatchState { subdomain: string; started_at: string; checked_through: string; last_success?: string }
interface ReplyUpdate { ticket_id: number; comment_id: number; author_id: number | null; public: boolean; created_at: string; detected_at: string }
const watchDir = (config: ZendeskMcpConfig) => path.join(path.dirname(config.tokenFilePath), `watch-${config.subdomain}`);

async function readState(dir: string): Promise<WatchState | null> {
  try { return JSON.parse(await fs.readFile(path.join(dir, "state.json"), "utf8")); }
  catch (err) { if ((err as NodeJS.ErrnoException).code === "ENOENT") return null; throw err; }
}
async function saveState(dir: string, state: WatchState) {
  const temp = path.join(dir, `state-${process.pid}.tmp`);
  await fs.writeFile(temp, JSON.stringify(state), { mode: 0o600 });
  await fs.rename(temp, path.join(dir, "state.json"));
}

export async function checkTicketReplies(client: Pick<ZendeskApiClient, "searchTickets" | "listTicketComments">, config: ZendeskMcpConfig) {
  const dir = watchDir(config);
  await fs.mkdir(path.join(dir, "replies"), { recursive: true, mode: 0o700 });
  const lock = path.join(dir, "poll.lock");
  try { await fs.writeFile(lock, String(process.pid), { flag: "wx", mode: 0o600 }); }
  catch (err) {
    if ((err as NodeJS.ErrnoException).code !== "EEXIST") throw err;
    const pid = Number(await fs.readFile(lock, "utf8"));
    try { process.kill(pid, 0); return { status: "check_already_running" }; }
    catch (e) { if ((e as NodeJS.ErrnoException).code !== "ESRCH") throw e; }
    await fs.unlink(lock);
    return checkTicketReplies(client, config);
  }
  try {
    const now = new Date().toISOString();
    let state = await readState(dir);
    if (!state) {
      state = { subdomain: config.subdomain, started_at: now, checked_through: now };
      await saveState(dir, state);
      return { status: "baseline_created", started_at: now, note: "Future comments will be recorded. Historical comments are not new replies." };
    }
    if (state.subdomain !== config.subdomain) throw new Error("Watcher tenant mismatch");
    // Revisit a full day to tolerate search indexing lag; comment IDs deduplicate overlap.
    const since = new Date(Math.max(Date.parse(state.started_at), Date.parse(state.checked_through) - 86400_000)).toISOString();
    let checked = 0, added = 0;
    for (let page = 1; page <= 10; page++) {
      const search = await client.searchTickets({ query: `updated>${since}`, page, perPage: 100, sortBy: "updated_at", sortOrder: "asc" });
      if (search.total_count > 1000) throw new Error("More than 1,000 tickets changed in the polling window. Checkpoint was not advanced. Narrow/split the window before resuming; updates may be incomplete.");
      for (const ticket of search.tickets) {
        checked++;
        let cursor: string | undefined;
        for (let p = 0; p < 100; p++) {
          const comments = await client.listTicketComments(ticket.id, { pageSize: 100, sortOrder: "desc", cursor });
          for (const comment of comments.comments) {
            if (Date.parse(comment.created_at) <= Date.parse(state.started_at) || Date.parse(comment.created_at) < Date.parse(since)) continue;
            const update: ReplyUpdate = { ticket_id: ticket.id, comment_id: comment.id, author_id: comment.author_id, public: comment.public, created_at: comment.created_at, detected_at: now };
            try { await fs.writeFile(path.join(dir, "replies", `${comment.id}.json`), JSON.stringify(update), { flag: "wx", mode: 0o600 }); added++; }
            catch (err) { if ((err as NodeJS.ErrnoException).code !== "EEXIST") throw err; }
          }
          if (!comments.has_more || comments.comments.some(c => Date.parse(c.created_at) < Date.parse(since))) break;
          if (!comments.next_cursor || p === 99) throw new Error("Comment pagination incomplete; checkpoint not advanced.");
          cursor = comments.next_cursor;
        }
      }
      if (!search.has_more) break;
    }
    state.checked_through = now; state.last_success = now;
    await saveState(dir, state);
    return { status: "ok", tickets_checked: checked, new_comments: added, checked_through: now, indexing_notice: "Search may lag. Polls revisit the previous day; comments indexed later than that can be missed." };
  } finally { await fs.unlink(lock); }
}

export async function readReplyInbox(config: ZendeskMcpConfig, since?: string, limit = 100) {
  const dir = watchDir(config);
  const state = await readState(dir);
  if (!state) return { status: "not_started", updates: [], has_more: false };
  const files = await fs.readdir(path.join(dir, "replies"));
  const updates: ReplyUpdate[] = [];
  for (const file of files.filter(f => /^\d+\.json$/.test(f))) {
    const update = JSON.parse(await fs.readFile(path.join(dir, "replies", file), "utf8")) as ReplyUpdate;
    if (!since || Date.parse(update.detected_at) > Date.parse(since)) updates.push(update);
  }
  updates.sort((a, b) => a.detected_at.localeCompare(b.detected_at) || a.comment_id - b.comment_id);
  // Include all records sharing the boundary timestamp so `since` cannot skip a batch.
  let end = Math.min(limit, updates.length);
  while (end < updates.length && updates[end].detected_at === updates[end - 1].detected_at) end++;
  const selected = updates.slice(0, end);
  return { status: "ok", watcher: state, updates: selected, has_more: end < updates.length, next_since: selected.at(-1)?.detected_at ?? since ?? null };
}
