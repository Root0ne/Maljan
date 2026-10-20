/**
 * What an audit row actually says, and which columns are worth drawing.
 *
 * The log had four columns and two of them were noise: RESOURCE read
 * "settings" on every visible row, restating the prefix of the ACTION beside
 * it, and IP ADDRESS was an em dash on all twenty. What it did not have was an
 * actor — the one thing an audit log exists to record. The endpoint carries
 * the actor's name beside `user_id`, so the name is what the row says, with
 * the id kept behind it.
 *
 * So the columns are decided from the page rather than written down: a column
 * every row leaves empty is not drawn, and the resource is folded into the
 * action unless it says something the action does not.
 */

import { humaniseKey } from "@/lib/humanise";
import type { AuditLogDTO } from "@/lib/api";

/** What a log row is drawn as. */
export interface AuditRow {
  id: string;
  at: string;
  action: string;
  /** The resource, when it is not already the action's own prefix. */
  resource: string;
  actor: string;
  /**
   * The actor's id, when the cell shows a name rather than the id itself. The
   * page keeps it as the cell's title, so two people under one display name
   * stay apart; it is empty when the id is already what the cell says.
   */
  actorId: string;
  ip: string;
  /** The resource's full id, kept as the cell's title where the cell shows
   *  eight characters of it; empty when it carries none. */
  resourceId: string;
  /** What the entry recorded beyond its columns, one `[key, value]` per field. */
  details: Array<[string, string]>;
}

/** The columns a page of rows has something to put in. */
export interface AuditColumns {
  resource: boolean;
  ip: boolean;
  details: boolean;
}

/** `settings.update` as a sentence, keeping every word the key carries. */
export function actionLabel(action: string): string {
  return humaniseKey(action) || action;
}

/**
 * Who did it.
 *
 * The endpoint resolves `user_id` to a name — the display name, or the local
 * part of the e-mail — and that name is what the row shows. It is null for a
 * principal the users table no longer holds, and eight characters of the id
 * stand in for it there. Both are null for the events that have no
 * authenticated principal — a failed sign-in, a lockout, a replayed refresh
 * token — and those are the platform's own, not nobody's.
 */
export function actorLabel(
  actor: string | null | undefined,
  userId: string | null | undefined
): string {
  const name = (actor ?? "").trim();
  if (name) return name;
  const id = (userId ?? "").trim();
  return id ? id.slice(0, 8) : "the platform";
}

/** The part of the resource the action has not already said. */
function resourceOf(log: AuditLogDTO): string {
  const type = (log.resource_type ?? "").trim();
  const id = (log.resource_id ?? "").trim();
  const prefix = log.action.split(".")[0];
  const name = type && type !== prefix ? type : "";
  if (name && id) return `${name} ${id.slice(0, 8)}`;
  if (name) return name;
  if (id) return id.slice(0, 8);
  return "";
}

/**
 * What an entry recorded beyond its columns, as `[key, value]` pairs.
 *
 * The endpoint returns `details` on every row — the key prefix an API key was
 * made with, the settings keys a save changed, why a sign-in was refused —
 * and the log dropped it, so an entry said that something happened and never
 * what. A value that is not text is written as JSON so nothing is lost.
 */
export function auditDetails(details: Record<string, unknown> | null | undefined): Array<[string, string]> {
  if (!details || typeof details !== "object") return [];
  return Object.entries(details).map(([key, value]) => {
    let text: string;
    if (typeof value === "string") text = value;
    else {
      try {
        text = JSON.stringify(value) ?? String(value);
      } catch {
        text = String(value);
      }
    }
    return [key, text];
  });
}

/** One page of log entries, as rows. */
export function auditRows(logs: AuditLogDTO[]): AuditRow[] {
  return logs.map((log) => {
    const actor = actorLabel(log.actor, log.user_id);
    const id = (log.user_id ?? "").trim();
    return {
      id: log.id,
      at: log.created_at,
      action: actionLabel(log.action),
      resource: resourceOf(log),
      actor,
      // The full id behind the cell whenever the cell does not already show
      // all of it: a name, or the eight characters that stand in for one.
      actorId: !id || actor === id ? "" : id,
      ip: (log.ip_address ?? "").trim(),
      resourceId: (log.resource_id ?? "").trim(),
      details: auditDetails(log.details),
    };
  });
}

/** Which of the optional columns this page has anything to put in. */
export function auditColumns(rows: AuditRow[]): AuditColumns {
  return {
    resource: rows.some((row) => row.resource !== ""),
    ip: rows.some((row) => row.ip !== ""),
    details: rows.some((row) => row.details.length > 0),
  };
}
