import { ZendeskMcpConfig } from "./config.js";
import {
  PolicyViolationError,
  RateLimitExceededError,
  RateLimitMetadata,
  ReauthorizationRequiredError,
  ZendeskApiError,
} from "./errors.js";
import { SafeLogger } from "./logger.js";
import { ZendeskOAuthManager } from "./oauth.js";
import { updateTicketSchema, replyTicketSchema, TicketUpdateInput, TicketReplyInput } from "./ticket-inputs.js";
import { downloadAttachment, MAX_ATTACHMENT_BYTES } from "./attachment-reader.js";
import {
  boundPlainText,
  enforceTicketSearchQuery,
  getTenantOrigin,
  inspectAttachmentUrl,
  parseTicketIdentifier,
  redactSecrets,
  sanitizeFileName,
  stripHtmlToText,
  validateOutboundRequest,
} from "./security.js";

class Semaphore {
  private active = 0;
  private readonly queue: Array<() => void> = [];

  constructor(private readonly maxConcurrency: number) {}

  public async acquire(): Promise<() => void> {
    if (this.active < this.maxConcurrency) {
      this.active += 1;
      return () => this.release();
    }
    return new Promise<() => void>((resolve) => {
      this.queue.push(() => {
        this.active += 1;
        resolve(() => this.release());
      });
    });
  }

  private release(): void {
    this.active = Math.max(0, this.active - 1);
    const next = this.queue.shift();
    if (next) {
      next();
    }
  }
}

export function parseRateLimitHeaders(headers: Headers): RateLimitMetadata {
  const parseHeaderInt = (names: string[]): number | undefined => {
    for (const name of names) {
      const val = headers.get(name);
      if (val !== null) {
        const parsed = Number.parseInt(val, 10);
        if (Number.isFinite(parsed) && parsed >= 0) {
          return parsed;
        }
      }
    }
    return undefined;
  };

  const limit = parseHeaderInt(["x-rate-limit", "ratelimit-limit"]);
  const remaining = parseHeaderInt([
    "x-rate-limit-remaining",
    "ratelimit-remaining",
  ]);
  const resetSeconds = parseHeaderInt(["ratelimit-reset", "x-rate-limit-reset"]);

  let retryAfterSeconds: number | undefined;
  const retryAfterRaw = headers.get("retry-after");
  if (retryAfterRaw !== null) {
    const trimmed = retryAfterRaw.trim();
    if (/^\d+$/.test(trimmed)) {
      retryAfterSeconds = Number.parseInt(trimmed, 10);
    } else {
      const dateMs = Date.parse(trimmed);
      if (!Number.isNaN(dateMs)) {
        retryAfterSeconds = Math.max(
          0,
          Math.ceil((dateMs - Date.now()) / 1000)
        );
      }
    }
  }

  return {
    limit,
    remaining,
    resetSeconds,
    retryAfterSeconds,
  };
}

export interface NormalizedCustomField {
  id: number;
  value: unknown;
  label?: string;
}

export interface NormalizedTicketResult {
  ticket: {
    id: number;
    url: string;
    agent_url: string;
    subject: string;
    status: string;
    priority: string | null;
    type: string | null;
    requester_id: number | null;
    submitter_id: number | null;
    assignee_id: number | null;
    organization_id: number | null;
    group_id: number | null;
    created_at: string;
    updated_at: string;
    tags: string[];
    custom_fields: NormalizedCustomField[];
    initial_description: string;
    description_note: string;
  };
  fetch_time: string;
  truncated: boolean;
  rate_limit?: RateLimitMetadata;
}

export interface NormalizedAttachment {
  id: number | null;
  file_name: string;
  content_type: string | null;
  size_bytes: number | null;
  inline: boolean;
  width: number | null;
  height: number | null;
  content_url: string | null;
  is_external_url: boolean;
  security_note: string;
}

export interface NormalizedComment {
  id: number;
  author_id: number | null;
  created_at: string;
  public: boolean;
  visibility: "PUBLIC" | "INTERNAL_PRIVATE_NOTE";
  plain_body: string;
  truncated: boolean;
  attachments: NormalizedAttachment[];
  inline_attachments: NormalizedAttachment[];
}

export interface NormalizedCommentsPageResult {
  ticket_id: number;
  comments: NormalizedComment[];
  comments_returned: number;
  page_size: number;
  sort_order: "asc" | "desc";
  has_more: boolean;
  next_cursor: string | null;
  continuation_notice: string;
  fetch_time: string;
  truncated: boolean;
  rate_limit?: RateLimitMetadata;
}

export interface NormalizedSearchTicketSummary {
  id: number;
  agent_url: string;
  subject: string;
  status: string;
  priority: string | null;
  ticket_type: string | null;
  requester_id: number | null;
  assignee_id: number | null;
  organization_id: number | null;
  group_id: number | null;
  created_at: string;
  updated_at: string;
  tags: string[];
  description_preview: string;
  truncated: boolean;
}

export interface NormalizedSearchResult {
  enforced_query: string;
  tickets: NormalizedSearchTicketSummary[];
  tickets_returned: number;
  total_count: number;
  page: number;
  per_page: number;
  has_more: boolean;
  next_page: number | null;
  search_cap_limit: number;
  search_cap_reached: boolean;
  continuation_notice: string;
  indexing_lag_notice: string;
  fetch_time: string;
  truncated: boolean;
  rate_limit?: RateLimitMetadata;
}

export interface NormalizedUserResult {
  user: {
    id: number;
    name: string;
    email: string | null;
    role: string | null;
    active: boolean;
    verified: boolean;
    organization_id: number | null;
    default_group_id: number | null;
    time_zone: string | null;
    locale: string | null;
    created_at: string | null;
    updated_at: string | null;
  };
  fetch_time: string;
  rate_limit?: RateLimitMetadata;
}

export interface ZendeskClientOptions {
  config: ZendeskMcpConfig;
  oauthManager: ZendeskOAuthManager;
  logger: SafeLogger;
  fetchFn?: typeof fetch;
  sleepFn?: (ms: number) => Promise<void>;
  customFieldsCacheTtlMs?: number;
}

export class ZendeskApiClient {
  private readonly config: ZendeskMcpConfig;
  private readonly oauthManager: ZendeskOAuthManager;
  private readonly logger: SafeLogger;
  private readonly fetchFn: typeof fetch;
  private readonly sleepFn: (ms: number) => Promise<void>;
  private readonly semaphore: Semaphore;
  private readonly customFieldsCacheTtlMs: number;

  private customFieldLabels: Map<number, string> | null = null;
  private customFieldLabelsExpiresAt = 0;

  constructor(options: ZendeskClientOptions) {
    this.config = options.config;
    this.oauthManager = options.oauthManager;
    this.logger = options.logger;
    this.fetchFn = options.fetchFn ?? globalThis.fetch;
    this.sleepFn =
      options.sleepFn ??
      ((ms: number) => new Promise((resolve) => setTimeout(resolve, ms)));
    this.semaphore = new Semaphore(this.config.maxConcurrentRequests);
    this.customFieldsCacheTtlMs =
      options.customFieldsCacheTtlMs ?? 10 * 60 * 1000;
  }

  public async listTicketFields() {
    const result = await this.getJson<{ ticket_fields?: Array<Record<string, unknown>> }>("/api/v2/ticket_fields.json");
    return { fields: result.data.ticket_fields ?? [], fetch_time: result.fetchTime };
  }

  public async getTicketAttachment(ticketIdOrUrl: number | string, attachmentId: number) {
    const ticketId = parseTicketIdentifier(ticketIdOrUrl, this.config.subdomain);
    if (!Number.isSafeInteger(attachmentId) || attachmentId <= 0) throw new PolicyViolationError("INVALID_ATTACHMENT_ID", "Attachment ID must be a positive safe integer.");
    let cursor: string | undefined;
    let found = false;
    for (let page = 0; page < 100; page++) {
      const comments = await this.listTicketComments(ticketId, { pageSize: 100, cursor });
      found = comments.comments.some(c => [...c.attachments, ...c.inline_attachments].some(a => a.id === attachmentId));
      if (found) break;
      if (!comments.has_more) throw new PolicyViolationError("ATTACHMENT_NOT_ON_TICKET", "Attachment is not present in this ticket's accessible comments.");
      if (!comments.next_cursor) throw new PolicyViolationError("ATTACHMENT_LOOKUP_INCOMPLETE", "Comment pagination has no usable continuation cursor.");
      cursor = comments.next_cursor;
    }
    if (!found) throw new PolicyViolationError("ATTACHMENT_LOOKUP_INCOMPLETE", "Attachment lookup exceeded 100 comment pages. No attachment downloaded.");
    const { data, fetchTime } = await this.getJson<{ attachment?: Record<string, unknown> }>(`/api/v2/attachments/${attachmentId}.json`);
    if (!data.attachment || data.attachment.id !== attachmentId) throw new ZendeskApiError(502, "Unexpected attachment metadata response.");
    const attachment = this.normalizeAttachment(data.attachment);
    return { ticket_id: ticketId, attachment: { ...attachment, deleted: data.attachment.deleted === true, malware_scan_result: typeof data.attachment.malware_scan_result === "string" ? data.attachment.malware_scan_result : "unknown" }, fetch_time: fetchTime };
  }

  public async readTicketAttachment(ticketIdOrUrl: number | string, attachmentId: number) {
    const metadata = await this.getTicketAttachment(ticketIdOrUrl, attachmentId);
    const attachment = metadata.attachment;
    if (attachment.deleted || attachment.malware_scan_result !== "malware_not_found") throw new PolicyViolationError("ATTACHMENT_NOT_CLEARED", "Attachment is deleted or has not passed Zendesk's malware scan. File content was not downloaded.");
    if (!attachment.content_url) throw new PolicyViolationError("UNSAFE_ATTACHMENT_URL", "No safe content URL is available.");
    if (attachment.size_bytes !== null && attachment.size_bytes > MAX_ATTACHMENT_BYTES) throw new PolicyViolationError("ATTACHMENT_TOO_LARGE", "Attachment exceeds the 10 MiB download limit.");
    const release = await this.semaphore.acquire();
    try {
      const accessToken = await this.oauthManager.getValidAccessToken();
      const content = await downloadAttachment({ url: attachment.content_url, subdomain: this.config.subdomain, accessToken, timeoutMs: this.config.requestTimeoutMs, fetchFn: this.fetchFn });
      return { metadata, ...content };
    } finally { release(); }
  }

  public async updateTicket(input: TicketUpdateInput) {
    const args = updateTicketSchema.parse(input);
    return this.putTicket(args.ticket_id, { ...args.fields, safe_update: true, updated_stamp: args.updated_stamp });
  }

  public async replyTicket(input: TicketReplyInput) {
    const args = replyTicketSchema.parse(input);
    this.requireWrites();
    const { user } = await this.getUser("me");
    return this.putTicket(args.ticket_id, {
      safe_update: true, updated_stamp: args.updated_stamp,
      ...(args.status ? { status: args.status } : {}),
      comment: { body: args.body, public: args.visibility === "public", author_id: user.id },
    });
  }

  private requireWrites(): void {
    if (!this.config.enableWrites || !this.config.oauthScopes.includes("tickets:write")) {
      throw new PolicyViolationError("WRITES_DISABLED", "Ticket writes require ZENDESK_ENABLE_WRITES=true and tickets:write consent.");
    }
  }

  private async putTicket(ticketIdOrUrl: number | string, ticket: Record<string, unknown>) {
    this.requireWrites();
    const id = parseTicketIdentifier(ticketIdOrUrl, this.config.subdomain);
    const url = validateOutboundRequest(new URL(`/api/v2/tickets/${id}.json`, getTenantOrigin(this.config.subdomain)), "PUT", this.config.subdomain, true);
    const release = await this.semaphore.acquire();
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), this.config.requestTimeoutMs);
    try {
      const accessToken = await this.oauthManager.getValidAccessToken();
      // Never retry writes automatically: a timeout or 5xx may follow a committed reply.
      const response = await this.fetchFn(url.toString(), {
        method: "PUT", redirect: "manual", signal: controller.signal,
        headers: { Authorization: `Bearer ${accessToken}`, Accept: "application/json", "Content-Type": "application/json" },
        body: JSON.stringify({ ticket }),
      });
      if (response.status === 409) throw new ZendeskApiError(409, "Ticket changed since it was reviewed. Read the latest ticket and comments before submitting a new update.", { errorCode: "update_conflict" });
      if (!response.ok) throw new ZendeskApiError(response.status, `Ticket update returned HTTP ${response.status}. No automatic retry was made. For 5xx or redirects, verify the ticket and comments before resubmitting.`, { errorCode: `http_${response.status}` });
      const data = await response.json() as { ticket?: { id: number; updated_at: string; status: string }; audit?: { id: number } };
      if (data.ticket?.id !== id) throw new Error("Unexpected update response");
      return { ticket_id: id, updated_at: data.ticket.updated_at, status: data.ticket.status, audit_id: data.audit?.id, fetch_time: new Date().toISOString() };
    } catch (err) {
      if (err instanceof ZendeskApiError) throw err;
      throw new ZendeskApiError(0, "Ticket update outcome is unknown. Read the ticket and comments before retrying to avoid duplicate replies.", { errorCode: "write_outcome_unknown" });
    } finally { clearTimeout(timeout); release(); }
  }

  /**
   * Retrieves a single ticket's metadata and initial description by positive ticket ID or configured-tenant URL.
   */
  public async getTicket(
    ticketIdOrUrl: number | string,
    options?: { resolveCustomFields?: boolean }
  ): Promise<NormalizedTicketResult> {
    const ticketId = parseTicketIdentifier(
      ticketIdOrUrl,
      this.config.subdomain
    );
    const shouldResolveFields =
      options?.resolveCustomFields ?? this.config.resolveCustomFields;

    const { data, rateLimit, fetchTime } = await this.getJson<{
      ticket?: Record<string, unknown>;
    }>(`/api/v2/tickets/${ticketId}.json`);

    const rawTicket = data.ticket;
    if (!rawTicket || typeof rawTicket !== "object") {
      throw new ZendeskApiError(
        502,
        `Unexpected response payload from Zendesk for ticket #${ticketId}.`
      );
    }

    let fieldLabels: Map<number, string> | null = null;
    const rawCustomFields = Array.isArray(rawTicket.custom_fields)
      ? (rawTicket.custom_fields as Array<{ id?: unknown; value?: unknown }>)
      : [];

    if (shouldResolveFields && rawCustomFields.length > 0) {
      fieldLabels = await this.getCustomFieldLabelMapSafe();
    }

    const customFields: NormalizedCustomField[] = rawCustomFields
      .filter((f) => typeof f?.id === "number")
      .map((f) => {
        const id = f.id as number;
        const label = fieldLabels?.get(id);
        return label !== undefined
          ? { id, value: f.value ?? null, label }
          : { id, value: f.value ?? null };
      });

    const rawDescription =
      typeof rawTicket.description === "string"
        ? rawTicket.description
        : "";
    const boundedDesc = boundPlainText(
      rawDescription,
      this.config.maxBodyChars
    );

    const origin = getTenantOrigin(this.config.subdomain);

    return {
      ticket: {
        id: typeof rawTicket.id === "number" ? rawTicket.id : ticketId,
        url: `${origin}/api/v2/tickets/${ticketId}.json`,
        agent_url: `${origin}/agent/tickets/${ticketId}`,
        subject:
          typeof rawTicket.subject === "string"
            ? rawTicket.subject
            : "(no subject)",
        status:
          typeof rawTicket.status === "string" ? rawTicket.status : "unknown",
        priority:
          typeof rawTicket.priority === "string" ? rawTicket.priority : null,
        type: typeof rawTicket.type === "string" ? rawTicket.type : null,
        requester_id:
          typeof rawTicket.requester_id === "number"
            ? rawTicket.requester_id
            : null,
        submitter_id:
          typeof rawTicket.submitter_id === "number"
            ? rawTicket.submitter_id
            : null,
        assignee_id:
          typeof rawTicket.assignee_id === "number"
            ? rawTicket.assignee_id
            : null,
        organization_id:
          typeof rawTicket.organization_id === "number"
            ? rawTicket.organization_id
            : null,
        group_id:
          typeof rawTicket.group_id === "number" ? rawTicket.group_id : null,
        created_at:
          typeof rawTicket.created_at === "string" ? rawTicket.created_at : "",
        updated_at:
          typeof rawTicket.updated_at === "string" ? rawTicket.updated_at : "",
        tags: Array.isArray(rawTicket.tags)
          ? rawTicket.tags.filter((t): t is string => typeof t === "string")
          : [],
        custom_fields: customFields,
        initial_description: boundedDesc.text,
        description_note:
          "IMPORTANT: initial_description is only the first message on the ticket. Call zendesk_list_ticket_comments to inspect the complete conversation thread, replies, internal notes, and attachments.",
      },
      fetch_time: fetchTime,
      truncated: boundedDesc.truncated,
      rate_limit: rateLimit,
    };
  }

  /**
   * Lists ticket comments using cursor pagination (`page[size]`, `page[after]`).
   */
  public async listTicketComments(
    ticketIdOrUrl: number | string,
    options?: {
      pageSize?: number;
      cursor?: string;
      sortOrder?: "asc" | "desc";
      includeInlineImages?: boolean;
    }
  ): Promise<NormalizedCommentsPageResult> {
    const ticketId = parseTicketIdentifier(
      ticketIdOrUrl,
      this.config.subdomain
    );
    const pageSize = Math.min(
      100,
      Math.max(1, Math.trunc(options?.pageSize ?? 50))
    );
    const sortOrder = options?.sortOrder ?? "asc";
    const includeInlineImages = options?.includeInlineImages ?? true;

    const query = new URLSearchParams();
    query.set("page[size]", String(pageSize));
    if (options?.cursor && options.cursor.trim()) {
      query.set("page[after]", options.cursor.trim());
    }
    if (includeInlineImages) {
      query.set("include_inline_images", "true");
    }
    query.set("sort", sortOrder === "desc" ? "-created_at" : "created_at");

    const { data, rateLimit, fetchTime } = await this.getJson<{
      comments?: Array<Record<string, unknown>>;
      meta?: {
        has_more?: boolean;
        after_cursor?: string | null;
      };
      links?: {
        next?: string | null;
      };
      next_page?: string | null;
    }>(`/api/v2/tickets/${ticketId}/comments.json`, query);

    const rawComments = Array.isArray(data.comments) ? data.comments : [];
    let anyTruncated = false;

    const comments: NormalizedComment[] = rawComments.map((raw) => {
      const isPublic = raw.public !== false;
      const rawPlain =
        typeof raw.plain_body === "string" && raw.plain_body.trim() !== ""
          ? raw.plain_body
          : typeof raw.body === "string"
          ? stripHtmlToText(raw.body)
          : typeof raw.html_body === "string"
          ? stripHtmlToText(raw.html_body)
          : "";

      const bounded = boundPlainText(rawPlain, this.config.maxBodyChars);
      if (bounded.truncated) {
        anyTruncated = true;
      }

      const rawAttachments = Array.isArray(raw.attachments)
        ? (raw.attachments as Array<Record<string, unknown>>)
        : [];
      const normalizedAllAttachments = rawAttachments.map((att) =>
        this.normalizeAttachment(att)
      );

      return {
        id: typeof raw.id === "number" ? raw.id : 0,
        author_id: typeof raw.author_id === "number" ? raw.author_id : null,
        created_at:
          typeof raw.created_at === "string" ? raw.created_at : "",
        public: isPublic,
        visibility: isPublic ? "PUBLIC" : "INTERNAL_PRIVATE_NOTE",
        plain_body: bounded.text,
        truncated: bounded.truncated,
        attachments: normalizedAllAttachments.filter((a) => !a.inline),
        inline_attachments: normalizedAllAttachments.filter((a) => a.inline),
      };
    });

    let nextCursor: string | null =
      typeof data.meta?.after_cursor === "string" &&
      data.meta.after_cursor.trim()
        ? data.meta.after_cursor.trim()
        : null;

    if (!nextCursor && typeof data.links?.next === "string") {
      try {
        const nextUrl = new URL(data.links.next);
        const extracted = nextUrl.searchParams.get("page[after]");
        if (extracted) {
          nextCursor = extracted;
        }
      } catch {
        // Ignore malformed links.next
      }
    }

    const hasMore =
      typeof data.meta?.has_more === "boolean"
        ? data.meta.has_more
        : Boolean(nextCursor || data.next_page);

    const continuationNotice = hasMore
      ? `MORE COMMENTS REMAIN: This response contains ${comments.length} comment(s) and is NOT the complete thread. Call zendesk_list_ticket_comments with cursor="${
          nextCursor ?? ""
        }" to fetch the next page.`
      : `END OF THREAD: All ${comments.length} comment(s) on this page retrieved; no further pages remain.`;

    return {
      ticket_id: ticketId,
      comments,
      comments_returned: comments.length,
      page_size: pageSize,
      sort_order: sortOrder,
      has_more: hasMore,
      next_cursor: hasMore ? nextCursor : null,
      continuation_notice: continuationNotice,
      fetch_time: fetchTime,
      truncated: anyTruncated,
      rate_limit: rateLimit,
    };
  }

  /**
   * Searches Zendesk tickets enforcing `type:ticket` and reporting the 1,000-result search cap and indexing lag.
   */
  public async searchTickets(options: {
    query: string;
    page?: number;
    perPage?: number;
    sortBy?:
      | "updated_at"
      | "created_at"
      | "priority"
      | "status"
      | "ticket_type";
    sortOrder?: "asc" | "desc";
  }): Promise<NormalizedSearchResult> {
    const enforcedQuery = enforceTicketSearchQuery(options.query);
    const page = Math.max(1, Math.trunc(options.page ?? 1));
    const perPage = Math.min(
      100,
      Math.max(1, Math.trunc(options.perPage ?? 25))
    );

    const SEARCH_CAP_LIMIT = 1000;
    if ((page - 1) * perPage >= SEARCH_CAP_LIMIT) {
      throw new PolicyViolationError(
        "SEARCH_RESULT_CAP_EXCEEDED",
        `Zendesk standard search is capped at ${SEARCH_CAP_LIMIT} results (requested page ${page} with per_page ${perPage}). Narrow your search query with date ranges, status, or tags.`
      );
    }

    const queryParams = new URLSearchParams();
    queryParams.set("query", enforcedQuery);
    queryParams.set("page", String(page));
    queryParams.set("per_page", String(perPage));
    if (options.sortBy) {
      queryParams.set("sort_by", options.sortBy);
    }
    if (options.sortOrder) {
      queryParams.set("sort_order", options.sortOrder);
    }

    const { data, rateLimit, fetchTime } = await this.getJson<{
      results?: Array<Record<string, unknown>>;
      count?: number;
      next_page?: string | null;
    }>("/api/v2/search.json", queryParams);

    const rawResults = Array.isArray(data.results) ? data.results : [];
    const origin = getTenantOrigin(this.config.subdomain);
    const previewLimit = Math.min(1000, this.config.maxBodyChars);
    let anyTruncated = false;

    const tickets: NormalizedSearchTicketSummary[] = rawResults
      .filter(
        (item) =>
          !item.result_type ||
          String(item.result_type).toLowerCase() === "ticket"
      )
      .map((item) => {
        const id = typeof item.id === "number" ? item.id : 0;
        const rawDesc =
          typeof item.description === "string" ? item.description : "";
        const boundedPreview = boundPlainText(rawDesc, previewLimit);
        if (boundedPreview.truncated) {
          anyTruncated = true;
        }
        return {
          id,
          agent_url: `${origin}/agent/tickets/${id}`,
          subject:
            typeof item.subject === "string" ? item.subject : "(no subject)",
          status: typeof item.status === "string" ? item.status : "unknown",
          priority: typeof item.priority === "string" ? item.priority : null,
          ticket_type:
            typeof item.type === "string"
              ? item.type
              : typeof item.ticket_type === "string"
              ? item.ticket_type
              : null,
          requester_id:
            typeof item.requester_id === "number" ? item.requester_id : null,
          assignee_id:
            typeof item.assignee_id === "number" ? item.assignee_id : null,
          organization_id:
            typeof item.organization_id === "number"
              ? item.organization_id
              : null,
          group_id: typeof item.group_id === "number" ? item.group_id : null,
          created_at:
            typeof item.created_at === "string" ? item.created_at : "",
          updated_at:
            typeof item.updated_at === "string" ? item.updated_at : "",
          tags: Array.isArray(item.tags)
            ? item.tags.filter((t): t is string => typeof t === "string")
            : [],
          description_preview: boundedPreview.text,
          truncated: boundedPreview.truncated,
        };
      });

    const totalCount =
      typeof data.count === "number" ? data.count : tickets.length;
    const reachedCap =
      totalCount > SEARCH_CAP_LIMIT || page * perPage >= SEARCH_CAP_LIMIT;
    const hasMoreWithinCap =
      Boolean(data.next_page) && page * perPage < SEARCH_CAP_LIMIT;
    const nextPage = hasMoreWithinCap ? page + 1 : null;

    let continuationNotice: string;
    if (hasMoreWithinCap) {
      continuationNotice = `More results available (showing page ${page}, ${tickets.length} of ${totalCount} total matches). Pass page=${nextPage} to continue.${
        totalCount > SEARCH_CAP_LIMIT
          ? ` Note: Zendesk search only serves the first ${SEARCH_CAP_LIMIT} results; narrow the query to inspect beyond ${SEARCH_CAP_LIMIT}.`
          : ""
      }`;
    } else if (reachedCap && totalCount > page * perPage) {
      continuationNotice = `SEARCH CAP REACHED: Zendesk search is capped at ${SEARCH_CAP_LIMIT} accessible results (total matches reported: ${totalCount}). Narrow your query with created/updated dates, status, or tags to inspect additional tickets.`;
    } else {
      continuationNotice = `End of search results (${tickets.length} returned on page ${page} of ${totalCount} total match(es)).`;
    }

    return {
      enforced_query: enforcedQuery,
      tickets,
      tickets_returned: tickets.length,
      total_count: totalCount,
      page,
      per_page: perPage,
      has_more: hasMoreWithinCap,
      next_page: nextPage,
      search_cap_limit: SEARCH_CAP_LIMIT,
      search_cap_reached: reachedCap,
      continuation_notice: continuationNotice,
      indexing_lag_notice:
        "NOTE: Zendesk search indexing may lag by several minutes after ticket creation or updates. For a known ticket ID, use zendesk_get_ticket directly to avoid indexing delay.",
      fetch_time: fetchTime,
      truncated: anyTruncated,
      rate_limit: rateLimit,
    };
  }

  /**
   * Resolves a Zendesk user by ID or `"me"` (current authenticated user).
   */
  public async getUser(
    userIdOrMe: number | string = "me"
  ): Promise<NormalizedUserResult> {
    let pathSegment: string;
    if (
      typeof userIdOrMe === "string" &&
      userIdOrMe.trim().toLowerCase() === "me"
    ) {
      pathSegment = "me";
    } else {
      const numeric =
        typeof userIdOrMe === "number"
          ? userIdOrMe
          : Number(String(userIdOrMe).trim());
      if (!Number.isSafeInteger(numeric) || numeric <= 0) {
        throw new PolicyViolationError(
          "INVALID_USER_ID",
          `User identifier must be "me" or a positive integer ID (got "${String(
            userIdOrMe
          )}").`
        );
      }
      pathSegment = String(numeric);
    }

    const { data, rateLimit, fetchTime } = await this.getJson<{
      user?: Record<string, unknown>;
    }>(`/api/v2/users/${pathSegment}.json`);

    const rawUser = data.user;
    if (!rawUser || typeof rawUser !== "object" || typeof rawUser.id !== "number") {
      throw new ZendeskApiError(
        404,
        `User "${pathSegment}" could not be resolved or is not accessible with current OAuth scopes.`
      );
    }

    return {
      user: {
        id: rawUser.id,
        name: typeof rawUser.name === "string" ? rawUser.name : "(unnamed)",
        email: typeof rawUser.email === "string" ? rawUser.email : null,
        role: typeof rawUser.role === "string" ? rawUser.role : null,
        active: rawUser.active !== false,
        verified: Boolean(rawUser.verified),
        organization_id:
          typeof rawUser.organization_id === "number"
            ? rawUser.organization_id
            : null,
        default_group_id:
          typeof rawUser.default_group_id === "number"
            ? rawUser.default_group_id
            : null,
        time_zone:
          typeof rawUser.time_zone === "string" ? rawUser.time_zone : null,
        locale: typeof rawUser.locale === "string" ? rawUser.locale : null,
        created_at:
          typeof rawUser.created_at === "string" ? rawUser.created_at : null,
        updated_at:
          typeof rawUser.updated_at === "string" ? rawUser.updated_at : null,
      },
      fetch_time: fetchTime,
      rate_limit: rateLimit,
    };
  }

  private normalizeAttachment(
    raw: Record<string, unknown>
  ): NormalizedAttachment {
    const fileName = sanitizeFileName(
      typeof raw.file_name === "string" ? raw.file_name : undefined
    );
    const inspectedUrl = inspectAttachmentUrl(
      typeof raw.content_url === "string" ? raw.content_url : undefined,
      this.config.subdomain
    );

    return {
      id: typeof raw.id === "number" ? raw.id : null,
      file_name: fileName,
      content_type:
        typeof raw.content_type === "string" ? raw.content_type : null,
      size_bytes: typeof raw.size === "number" ? raw.size : null,
      inline: Boolean(raw.inline),
      width: typeof raw.width === "number" ? raw.width : null,
      height: typeof raw.height === "number" ? raw.height : null,
      content_url: inspectedUrl.contentUrl,
      is_external_url: inspectedUrl.isExternalUrl,
      security_note: inspectedUrl.securityNote,
    };
  }

  private async getCustomFieldLabelMapSafe(): Promise<Map<
    number,
    string
  > | null> {
    if (
      this.customFieldLabels &&
      Date.now() < this.customFieldLabelsExpiresAt
    ) {
      return this.customFieldLabels;
    }

    try {
      const { data } = await this.getJson<{
        ticket_fields?: Array<{ id?: unknown; title?: unknown }>;
      }>("/api/v2/ticket_fields.json");

      const map = new Map<number, string>();
      if (Array.isArray(data.ticket_fields)) {
        for (const field of data.ticket_fields) {
          if (
            typeof field?.id === "number" &&
            typeof field?.title === "string"
          ) {
            map.set(field.id, field.title);
          }
        }
      }
      this.customFieldLabels = map;
      this.customFieldLabelsExpiresAt =
        Date.now() + this.customFieldsCacheTtlMs;
      return map;
    } catch (err) {
      this.logger.debug(
        "Could not resolve custom ticket field titles; preserving raw custom field IDs and values.",
        {
          reason: err instanceof Error ? err.message : String(err),
        }
      );
      return null;
    }
  }

  private async getJson<T>(
    pathname: string,
    query?: URLSearchParams
  ): Promise<{
    data: T;
    rateLimit: RateLimitMetadata;
    fetchTime: string;
  }> {
    const origin = getTenantOrigin(this.config.subdomain);
    const fullUrl = new URL(pathname, origin);
    if (query) {
      fullUrl.search = query.toString();
    }

    // Strict allowlist & GET-only verification before acquiring token or network slot
    const validatedUrl = validateOutboundRequest(
      fullUrl,
      "GET",
      this.config.subdomain
    );

    const release = await this.semaphore.acquire();
    try {
      return await this.executeGetWithRetries<T>(validatedUrl);
    } finally {
      release();
    }
  }

  private async executeGetWithRetries<T>(validatedUrl: URL): Promise<{
    data: T;
    rateLimit: RateLimitMetadata;
    fetchTime: string;
  }> {
    let refreshedAfter401 = false;
    let attempt = 0;

    while (true) {
      const accessToken = await this.oauthManager.getValidAccessToken();
      const controller = new AbortController();
      const timeoutId = setTimeout(
        () => controller.abort(),
        this.config.requestTimeoutMs
      );

      let response: Response;
      try {
        response = await this.fetchFn(validatedUrl.toString(), {
          method: "GET",
          headers: {
            Authorization: `Bearer ${accessToken}`,
            Accept: "application/json",
            "User-Agent": "zendesk-mcp/0.1.0",
          },
          redirect: "manual",
          signal: controller.signal,
        });
      } catch (err) {
        clearTimeout(timeoutId);
        const cause =
          err instanceof Error && "cause" in err && err.cause
            ? ` (${
                err.cause instanceof Error
                  ? err.cause.message
                  : String(err.cause)
              })`
            : "";
        const msg = redactSecrets(
          `${err instanceof Error ? err.message : String(err)}${cause}`,
          this.oauthManager.getKnownSecrets()
        );

        if (attempt < this.config.maxRetries) {
          attempt += 1;
          const waitMs = Math.min(2000, 500 * Math.pow(2, attempt - 1));
          this.logger.warn(
            `Transient network error requesting ${validatedUrl.pathname}; retrying in ${waitMs}ms (attempt ${attempt}/${this.config.maxRetries}): ${msg}`
          );
          await this.sleepFn(waitMs);
          continue;
        }

        throw new ZendeskApiError(
          0,
          `Network error requesting ${validatedUrl.pathname}: ${msg}`
        );
      } finally {
        clearTimeout(timeoutId);
      }

      const fetchTime = new Date().toISOString();
      const rateLimit = parseRateLimitHeaders(response.headers);

      // Block unexpected redirects so credentials are never forwarded elsewhere
      if (response.status >= 300 && response.status < 400) {
        const location = response.headers.get("location") ?? "(unknown)";
        throw new PolicyViolationError(
          "UNEXPECTED_REDIRECT",
          `Refusing to follow HTTP ${response.status} redirect from ${validatedUrl.pathname} to "${location}".`
        );
      }

      // Handle 401 Unauthorized by attempting a single coordinated token refresh
      if (response.status === 401) {
        if (!refreshedAfter401) {
          refreshedAfter401 = true;
          this.logger.warn(
            "Received HTTP 401 from Zendesk API; refreshing OAuth token and retrying once.",
            { path: validatedUrl.pathname }
          );
          await this.oauthManager.getValidAccessToken({
            forceRefresh: true,
            failedAccessToken: accessToken,
          });
          continue;
        }
        throw new ReauthorizationRequiredError(
          "http_401_after_refresh",
          `Zendesk API returned 401 Unauthorized for ${validatedUrl.pathname} even after refreshing the OAuth token. Run 'npm run auth' to reauthorize.`
        );
      }

      // Handle 429 Too Many Requests using Retry-After
      if (response.status === 429) {
        const retrySec = rateLimit.retryAfterSeconds ?? Math.pow(2, attempt + 1);
        const waitMs = Math.max(250, retrySec * 1000);

        if (
          attempt >= this.config.maxRetries ||
          waitMs > this.config.maxRetryAfterMs
        ) {
          throw new RateLimitExceededError(
            `Zendesk rate limit exceeded on ${validatedUrl.pathname} (HTTP 429). Retry-After is ${retrySec}s (max wait ${Math.round(
              this.config.maxRetryAfterMs / 1000
            )}s, attempt ${attempt + 1}/${this.config.maxRetries + 1}).`,
            rateLimit
          );
        }

        attempt += 1;
        this.logger.warn(
          `Zendesk rate limit hit (HTTP 429); waiting ${waitMs}ms before retry ${attempt}/${this.config.maxRetries}.`,
          {
            path: validatedUrl.pathname,
            retryAfterSeconds: retrySec,
          }
        );
        await this.sleepFn(waitMs);
        continue;
      }

      const rawText = await response.text();

      if (!response.ok) {
        const safeSnippet = redactSecrets(
          rawText.slice(0, 400),
          this.oauthManager.getKnownSecrets()
        );

        if (response.status === 403) {
          throw new ZendeskApiError(
            403,
            `Permission denied (HTTP 403) accessing ${validatedUrl.pathname}. Verify your Zendesk agent role/group visibility and that your OAuth token includes the required read scope (e.g. 'tickets:read' or 'users:read'). Details: ${safeSnippet}`,
            { errorCode: "forbidden", rateLimit }
          );
        }

        if (response.status === 404) {
          throw new ZendeskApiError(
            404,
            `Resource not found (HTTP 404) at ${validatedUrl.pathname}. Verify the ID exists in tenant "${this.config.subdomain}" and is visible to your agent role.`,
            { errorCode: "not_found", rateLimit }
          );
        }

        throw new ZendeskApiError(
          response.status,
          `Zendesk API returned HTTP ${response.status} for ${validatedUrl.pathname}: ${safeSnippet}`,
          { errorCode: `http_${response.status}`, rateLimit }
        );
      }

      let parsed: T;
      try {
        parsed = JSON.parse(rawText) as T;
      } catch {
        throw new ZendeskApiError(
          response.status,
          `Failed to parse JSON response from ${validatedUrl.pathname}.`,
          { rateLimit }
        );
      }

      return {
        data: parsed,
        rateLimit,
        fetchTime,
      };
    }
  }
}
