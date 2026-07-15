export function validateEmail(email: string): boolean {
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return emailRegex.test(email);
}

export function validateUrl(url: string): boolean {
  try {
    new URL(url);
    return true;
  } catch {
    return false;
  }
}

export function validateUuid(uuid: string): boolean {
  const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
  return uuidRegex.test(uuid);
}

export function validateRequired(value: unknown): boolean {
  if (value === null || value === undefined) return false;
  if (typeof value === 'string') return value.trim().length > 0;
  if (Array.isArray(value)) return value.length > 0;
  return true;
}

export function validateMinLength(value: string, min: number): boolean {
  return value.length >= min;
}

export function validateMaxLength(value: string, max: number): boolean {
  return value.length <= max;
}

export function validateFileSize(file: File, maxSizeMB: number): boolean {
  const maxBytes = maxSizeMB * 1024 * 1024;
  return file.size <= maxBytes;
}

export function validateFileType(file: File, allowedTypes: string[]): boolean {
  return allowedTypes.some(type => {
    if (type.endsWith('/*')) {
      return file.type.startsWith(type.slice(0, -1));
    }
    return file.type === type;
  });
}

export function validateHex(hex: string): boolean {
  return /^[0-9a-fA-F]+$/.test(hex);
}

export function validateBase64(base64: string): boolean {
  try {
    return btoa(atob(base64)) === base64;
  } catch {
    return false;
  }
}

export interface ValidationResult {
  valid: boolean;
  errors: string[];
}

export function validateForm<T extends Record<string, unknown>>(
  data: T,
  rules: Record<keyof T, Array<(value: unknown) => boolean | string>>
): ValidationResult {
  const errors: string[] = [];
  
  for (const [field, validators] of Object.entries(rules)) {
    const value = data[field as keyof T];
    
    for (const validator of validators) {
      const result = validator(value);
      if (result !== true) {
        errors.push(typeof result === 'string' ? result : `${field} is invalid`);
        break;
      }
    }
  }
  
  return {
    valid: errors.length === 0,
    errors,
  };
}