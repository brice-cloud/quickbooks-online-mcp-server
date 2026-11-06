import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { ToolDefinition } from "../types/tool-definition.js";
import { z } from "zod";

/**
 * Defines CRUD categories for tools
 */
export const CRUD_CATEGORY = {
  WRITE:  "WRITE",
  UPDATE: "UPDATE",
  DELETE: "DELETE",
  READ:   "READ",
} as const;

export type CrudCategory = typeof CRUD_CATEGORY[keyof typeof CRUD_CATEGORY];

/** 
 * Maps each CRUD category to its corresponding environment variable for disabling tools.
 */
export const DISABLE_ENV = {
  [CRUD_CATEGORY.WRITE]:  "QUICKBOOKS_DISABLE_WRITE",
  [CRUD_CATEGORY.UPDATE]: "QUICKBOOKS_DISABLE_UPDATE",
  [CRUD_CATEGORY.DELETE]: "QUICKBOOKS_DISABLE_DELETE",
} as const;

/** 
 * Maps every non-READ verb prefix to its category. Handles both underscore
 * and legacy hyphen separator variants (e.g. create-bill, update-vendor).
 * Insertion order is preserved in V8; all prefixes are distinct so order
 * does not affect correctness.
 */
export const PREFIX_CATEGORY_MAP: Record<string, CrudCategory> = {
  "create_": CRUD_CATEGORY.WRITE,
  "create-": CRUD_CATEGORY.WRITE,
  "update_": CRUD_CATEGORY.UPDATE,
  "update-": CRUD_CATEGORY.UPDATE,
  "delete_": CRUD_CATEGORY.DELETE,
  "delete-": CRUD_CATEGORY.DELETE,
};

/** 
 * Determines the CRUD category of a tool based on its name prefix.
 * Defaults to READ if no prefix matches.
 */
export function getCrudCategory(toolName: string): CrudCategory {
  for (const [prefix, category] of Object.entries(PREFIX_CATEGORY_MAP)) {
    if (toolName.startsWith(prefix)) return category;
  }
  return CRUD_CATEGORY.READ;
}

/**
 * Future narrow writes, such as a reviewed sandbox `create_deposit` trial,
 * require a code change that adds the tool name to this list.
 * The list is intentionally empty. Environment variables and the token file
 * cannot add to it.
 */
export const SANDBOX_WRITE_EXCEPTIONS: readonly string[] = Object.freeze([]);

/**
 * Read tools this fork may register. A name that is not on this list is not
 * registered, including new tools and any create/update/delete name.
 * QUICKBOOKS_DISABLE_WRITE, QUICKBOOKS_DISABLE_UPDATE, and QUICKBOOKS_DISABLE_DELETE
 * cannot turn a tool on. Setting them to "false" does not unlock writes.
 */
export const READ_ONLY_TOOL_ALLOWLIST: ReadonlySet<string> = new Set([
  "get-bill",
  "get-vendor",
  "get_account",
  "get_aged_payables",
  "get_aged_receivables",
  "get_attachable",
  "get_balance_sheet",
  "get_bill_payment",
  "get_cash_flow",
  "get_class",
  "get_company_info",
  "get_credit_memo",
  "get_customer",
  "get_customer_balance",
  "get_customer_sales",
  "get_department",
  "get_deposit",
  "get_employee",
  "get_estimate",
  "get_general_ledger",
  "get_invoice_pdf",
  "get_journal_entry",
  "get_payment",
  "get_payment_method",
  "get_preferences",
  "get_profit_and_loss",
  "get_purchase",
  "get_purchase_order",
  "get_refund_receipt",
  "get_sales_receipt",
  "get_tax_agency",
  "get_tax_code",
  "get_tax_rate",
  "get_term",
  "get_time_activity",
  "get_transfer",
  "get_trial_balance",
  "get_vendor_balance",
  "get_vendor_credit",
  "get_vendor_expenses",
  "read_invoice",
  "read_item",
  "search_accounts",
  "search_attachables",
  "search_bill_payments",
  "search_bills",
  "search_budgets",
  "search_classes",
  "search_credit_memos",
  "search_customers",
  "search_departments",
  "search_deposits",
  "search_employees",
  "search_estimates",
  "search_invoices",
  "search_items",
  "search_journal_entries",
  "search_payment_methods",
  "search_payments",
  "search_purchase_orders",
  "search_purchases",
  "search_refund_receipts",
  "search_sales_receipts",
  "search_tax_agencies",
  "search_tax_codes",
  "search_tax_rates",
  "search_terms",
  "search_time_activities",
  "search_transfers",
  "search_vendor_credits",
  "search_vendors",
]);

/**
 * Mutating tools are always disabled in this fork unless the name is listed in
 * SANDBOX_WRITE_EXCEPTIONS. Read tools register only when they are on the allowlist.
 * The DISABLE_* environment variables are ignored so a token file cannot turn writes on.
 */
export function isToolDisabled(
  toolName: string,
  exceptions: readonly string[] = SANDBOX_WRITE_EXCEPTIONS
): boolean {
  if (exceptions.includes(toolName)) return false;
  if (getCrudCategory(toolName) !== CRUD_CATEGORY.READ) return true;
  return !READ_ONLY_TOOL_ALLOWLIST.has(toolName);
}

/** 
 * Registers a tool when this sandbox fork's allowlist permits it.
 * create_, update_, and delete_ tools are not registered. Env flags cannot enable them.
 */
/**
 * Unsupported-parameter reporting.
 *
 * Tool schemas are strict zod objects, so a parameter a tool does not declare is
 * SILENTLY DISCARDED during validation: the call succeeds, the value never
 * reaches QuickBooks, and the caller has no way to find out. In practice this
 * surfaced as an invoice sent to a customer with a blank Ship Date — the caller
 * passed `ship_date`, `create_invoice` did not declare it, and nothing said so.
 *
 * Hard-failing on unknown keys would turn a harmless stray parameter into a
 * failed transaction, so instead the schema is registered permissively (unknown
 * keys survive validation and can therefore be seen), the wrapper STRIPS them
 * before the handler runs, and the response names them.
 */

/** Top-level keys a tool's params schema declares, or null if not an object schema. */
export function knownParamKeys(schema: unknown): Set<string> | null {
  const shape = (schema as any)?._def?.shape;
  if (!shape) return null;
  try {
    return new Set(Object.keys(typeof shape === "function" ? shape() : shape));
  } catch {
    return null;
  }
}

/** Keep unknown keys through validation so they can be reported rather than vanish. */
export function permissiveParamsSchema<T>(schema: T): T {
  const anySchema = schema as any;
  return typeof anySchema?.passthrough === "function" ? anySchema.passthrough() : schema;
}

/** Human-readable notice naming parameters the tool does not support. */
export function unsupportedParamsWarning(
  toolName: string,
  known: Set<string> | null,
  params: unknown
): string | null {
  if (!known || !params || typeof params !== "object" || Array.isArray(params)) return null;
  const extras = Object.keys(params as Record<string, unknown>).filter((k) => !known.has(k));
  if (extras.length === 0) return null;
  return (
    `WARNING: ${toolName} does not support ${extras.length === 1 ? "this parameter" : "these parameters"}: ` +
    `${extras.join(", ")}. ${extras.length === 1 ? "It was" : "They were"} IGNORED - the value did not reach ` +
    `QuickBooks. Supported parameters: ${[...known].sort().join(", ")}.`
  );
}

export function RegisterTool<T extends z.ZodType<any, any>>(
  server: McpServer,
  toolDefinition: ToolDefinition<T>
) {
  if (isToolDisabled(toolDefinition.name)) return;

  const known = knownParamKeys(toolDefinition.schema);
  const paramsSchema = permissiveParamsSchema(toolDefinition.schema);
  const baseHandler = toolDefinition.handler as unknown as (...a: any[]) => Promise<any>;

  const handler = (async (...a: any[]) => {
    let callArgs = a;
    let warning: string | null = null;
    try {
      const params = (a[0] as any)?.params;
      warning = unsupportedParamsWarning(toolDefinition.name, known, params);
      if (warning && known && params && typeof params === "object" && !Array.isArray(params)) {
        // Strip unknown keys before the handler runs. The permissive schema
        // exists only so they can be SEEN; it must not change what reaches
        // QuickBooks. Several search tools destructure their params with a rest
        // element and pass the rest on as query criteria (search-bills,
        // search-customers, search-estimates, search-vendors), so an unknown key
        // left in place would become a real SQL filter - quietly changing which
        // records the search returns while this warning claimed it was ignored.
        const cleaned: Record<string, unknown> = {};
        for (const [k, v] of Object.entries(params as Record<string, unknown>)) {
          if (known.has(k)) cleaned[k] = v;
        }
        callArgs = [{ ...(a[0] as any), params: cleaned }, ...a.slice(1)];
      }
    } catch {
      /* diagnostics must never break a working call */
    }

    const result = await baseHandler(...callArgs);

    try {
      if (warning && result && Array.isArray(result.content)) {
        // Prepended so it cannot be missed, and added even on error responses.
        result.content.unshift({ type: "text" as const, text: warning });
      }
    } catch {
      /* diagnostics must never break a working call */
    }
    return result;
  }) as typeof toolDefinition.handler;

  server.tool(toolDefinition.name, toolDefinition.description, { params: paramsSchema }, handler);
}