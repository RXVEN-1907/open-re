export function debounce<T extends (...args: unknown[]) => unknown>(
  func: T,
  wait: number,
  immediate = false
): (...args: Parameters<T>) => void {
  let timeout: ReturnType<typeof setTimeout> | null = null;
  
  return (...args: Parameters<T>) => {
    const later = () => {
      timeout = null;
      if (!immediate) func(...args);
    };
    
    const callNow = immediate && !timeout;
    
    if (timeout) clearTimeout(timeout);
    timeout = setTimeout(later, wait);
    
    if (callNow) func(...args);
  };
}

export function throttle<T extends (...args: unknown[]) => unknown>(
  func: T,
  limit: number
): (...args: Parameters<T>) => void {
  let inThrottle = false;
  
  return (...args: Parameters<T>) => {
    if (!inThrottle) {
      func(...args);
      inThrottle = true;
      setTimeout(() => (inThrottle = false), limit);
    }
  };
}

export function debouncePromise<T extends (...args: unknown[]) => Promise<unknown>>(
  func: T,
  wait: number
): (...args: Parameters<T>) => Promise<Awaited<ReturnType<T>>> {
  let timeout: ReturnType<typeof setTimeout> | null = null;
  let pendingResolve: (value: Awaited<ReturnType<T>>) => void;
  let pendingReject: (reason: unknown) => void;
  let pendingPromise: Promise<Awaited<ReturnType<T>>> | null = null;
  
  return (...args: Parameters<T>) => {
    if (pendingPromise) {
      return pendingPromise;
    }
    
    pendingPromise = new Promise((resolve, reject) => {
      pendingResolve = resolve;
      pendingReject = reject;
      
      if (timeout) clearTimeout(timeout);
      timeout = setTimeout(async () => {
        timeout = null;
        pendingPromise = null;
        
        try {
          const result = await func(...args);
          pendingResolve(result);
        } catch (error) {
          pendingReject(error);
        }
      }, wait);
    });
    
    return pendingPromise;
  };
}