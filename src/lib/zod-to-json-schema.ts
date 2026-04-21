// Minimal Zod -> JSON Schema converter.
//
// Scope: only what the netrecon tool registry actually uses:
//   z.object({ key: z.string().min(1), other: z.array(z.string()).optional() })
//   z.string(), z.string().min(n), z.string().url()
//   z.array(innerSchema)
//   z.optional(innerSchema)
//
// We walk Zod's internal `_def` representation. That's why this project pins
// `zod` to an exact version in package.json - a minor Zod bump could rename
// those internals out from under us. Unit tests would catch it immediately.

import type { ZodType, ZodTypeAny } from 'zod';

export interface JsonSchema {
  type?: string | string[];
  properties?: Record<string, JsonSchema>;
  required?: string[];
  items?: JsonSchema;
  minLength?: number;
  format?: string;
  description?: string;
  additionalProperties?: boolean;
}

interface ZodDef {
  typeName: string;
  checks?: Array<{ kind: string; value?: unknown }>;
  innerType?: ZodTypeAny;
  type?: ZodTypeAny;
  shape?: () => Record<string, ZodTypeAny>;
}

function defOf(schema: ZodTypeAny): ZodDef {
  return (schema as unknown as { _def: ZodDef })._def;
}

export function toJsonSchema(schema: ZodType<unknown>): JsonSchema {
  const def = defOf(schema as ZodTypeAny);

  switch (def.typeName) {
    case 'ZodObject': {
      const shape = def.shape ? def.shape() : {};
      const properties: Record<string, JsonSchema> = {};
      const required: string[] = [];
      for (const [key, value] of Object.entries(shape)) {
        const childDef = defOf(value);
        const isOptional = childDef.typeName === 'ZodOptional';
        properties[key] = toJsonSchema(value);
        if (!isOptional) required.push(key);
      }
      const out: JsonSchema = {
        type: 'object',
        properties,
        additionalProperties: false,
      };
      if (required.length > 0) out.required = required;
      return out;
    }

    case 'ZodString': {
      const out: JsonSchema = { type: 'string' };
      for (const check of def.checks ?? []) {
        if (check.kind === 'min' && typeof check.value === 'number') {
          out.minLength = check.value;
        } else if (check.kind === 'url') {
          out.format = 'uri';
        }
      }
      return out;
    }

    case 'ZodArray': {
      const inner = def.type;
      return {
        type: 'array',
        items: inner ? toJsonSchema(inner) : {},
      };
    }

    case 'ZodOptional': {
      const inner = def.innerType;
      return inner ? toJsonSchema(inner) : {};
    }

    default:
      // Unsupported Zod type - return an empty schema rather than throw so
      // tools/list still works. Tests should catch unsupported usage.
      return {};
  }
}
