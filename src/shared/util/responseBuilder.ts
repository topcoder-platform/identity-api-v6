import { HttpStatus } from '@nestjs/common';

export interface BaseResponse<T> {
  result: {
    success: boolean;
    status: number;
    metadata: any;
    content: T;
  };
  version: string;
}

export function createBaseResponse<T extends object>(
  data: T,
  status = HttpStatus.OK,
  fields?: string,
): BaseResponse<T> {
  return {
    result: {
      success: true,
      status,
      metadata: null,
      content: filterFieldsNested(data, fields),
    },
    version: 'v6',
  };
}

export function createErrorResponse(
  message: string,
  status: number = HttpStatus.INTERNAL_SERVER_ERROR,
): BaseResponse<{ error: string }> {
  return {
    result: {
      success: false,
      status,
      metadata: null,
      content: { error: message },
    },
    version: 'v6',
  };
}

export function filterFieldsNested<T extends object>(
  data: T,
  fields?: string,
  excludeFields?: string[],
): any {
  const parsedFields = fields
    ?.split(',')
    .map((f) => f.trim())
    .filter(Boolean);

  // If no fields specified, return all except excluded
  if (!parsedFields || parsedFields.length === 0) {
    if (!excludeFields || excludeFields.length === 0) {
      return data;
    }

    const filtered: any = {};
    for (const key in data) {
      if (!excludeFields.includes(key)) {
        filtered[key] = data[key];
      }
    }
    return filtered;
  }

  // Separate regular fields from nested fields
  const regularFields: string[] = [];
  const nestedFields: { [key: string]: string[] } = {};

  parsedFields.forEach((field) => {
    if (field.includes('.')) {
      const [parentKey, childKey] = field.split('.', 2);
      if (!nestedFields[parentKey]) {
        nestedFields[parentKey] = [];
      }
      nestedFields[parentKey].push(childKey);
    } else {
      regularFields.push(field);
    }
  });

  const filtered: any = {};

  // Add regular fields
  for (const key of regularFields) {
    if (excludeFields && excludeFields.includes(key)) {
      continue;
    }

    if (key in data) {
      filtered[key] = data[key];
    } else {
      console.warn(`Field '${key}' does not exist in object`);
    }
  }

  // Handle nested fields
  for (const [parentKey, childKeys] of Object.entries(nestedFields)) {
    if (excludeFields && excludeFields.includes(parentKey)) {
      continue;
    }

    if (parentKey in data) {
      const parentValue = (data as any)[parentKey];

      if (Array.isArray(parentValue)) {
        // Filter each object in the array
        filtered[parentKey] = parentValue.map((item) => {
          if (item && typeof item === 'object') {
            const filteredItem: any = {};
            for (const childKey of childKeys) {
              if (childKey in item) {
                filteredItem[childKey] = item[childKey];
              }
            }
            return filteredItem;
          }
          return item;
        });
      } else if (parentValue && typeof parentValue === 'object') {
        // Filter single object
        const filteredObject: any = {};
        for (const childKey of childKeys) {
          if (childKey in parentValue) {
            filteredObject[childKey] = parentValue[childKey];
          }
        }
        filtered[parentKey] = filteredObject;
      }
    } else {
      console.warn(`Parent field '${parentKey}' does not exist in object`);
    }
  }

  return filtered;
}
