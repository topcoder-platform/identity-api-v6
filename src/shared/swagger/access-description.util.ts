import { EOL } from 'os';

export interface AccessDescriptionOptions {
  summary: string;
  jwt?: string | string[];
  m2m?: string | string[];
  notes?: string | string[];
}

function formatSegment(
  value: string | string[] | undefined,
  emptyFallback: string,
): string {
  if (Array.isArray(value)) {
    if (!value.length) {
      return emptyFallback;
    }
    return value.map((item) => `\`${item}\``).join(', ');
  }

  if (typeof value === 'string' && value.trim().length > 0) {
    return value.trim();
  }

  return emptyFallback;
}

export function describeAccess({
  summary,
  jwt,
  m2m,
  notes,
}: AccessDescriptionOptions): string {
  const pieces: string[] = [summary.trim()];

  pieces.push(
    '',
    `**JWT access:** ${formatSegment(jwt, 'Any authenticated user.')}`,
  );

  pieces.push(
    '',
    `**M2M scopes:** ${formatSegment(m2m, 'Not supported.')}`,
  );

  if (notes) {
    const noteItems = Array.isArray(notes) ? notes : [notes];
    for (const note of noteItems) {
      if (note && note.trim().length) {
        pieces.push('', note.trim());
      }
    }
  }

  return pieces.join(EOL);
}
