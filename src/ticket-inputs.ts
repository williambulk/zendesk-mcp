import { z } from "zod";

const id = z.number().int().positive().safe();
export const ticketIdSchema = z.union([id, z.string().min(1)]);
export const stampSchema = z.iso.datetime({ offset: true });
export const ticketFieldsSchema = z.strictObject({
  subject: z.string().trim().min(1).max(1000).optional(),
  status: z.enum(["new", "open", "pending", "hold", "solved"]).optional(),
  priority: z.enum(["low", "normal", "high", "urgent"]).nullable().optional(),
  type: z.enum(["problem", "incident", "question", "task"]).nullable().optional(),
  assignee_id: id.nullable().optional(),
  group_id: id.optional(),
  organization_id: id.nullable().optional(),
  ticket_form_id: id.optional(),
  custom_status_id: id.optional(),
  due_at: stampSchema.nullable().optional(),
  tags: z.array(z.string().min(1).max(200)).max(100).optional(),
  custom_fields: z.array(z.strictObject({
    id,
    value: z.union([z.string().max(16000), z.number().finite(), z.boolean(), z.array(z.string()).max(100), z.null()]),
  })).max(100).optional(),
}).refine(v => Object.keys(v).length > 0, "Provide at least one field to update.")
  .refine(v => !v.custom_fields || new Set(v.custom_fields.map(f => f.id)).size === v.custom_fields.length, "Duplicate custom field IDs are not allowed.");

export const updateTicketSchema = z.strictObject({
  ticket_id: ticketIdSchema,
  updated_stamp: stampSchema.describe("Exact updated_at from the ticket you reviewed. A newer update causes a conflict; review it before trying again."),
  fields: ticketFieldsSchema,
});
export const replyTicketSchema = z.strictObject({
  ticket_id: ticketIdSchema,
  updated_stamp: stampSchema,
  body: z.string().trim().min(1).max(16000),
  visibility: z.enum(["public", "internal"]).describe("Public replies may email the requester and CCs. Internal notes are visible to agents."),
  status: z.enum(["open", "pending", "hold", "solved"]).optional(),
});
export type TicketUpdateInput = z.infer<typeof updateTicketSchema>;
export type TicketReplyInput = z.infer<typeof replyTicketSchema>;
