/**
 * A generation per probed key, so a probe that lands after an edit is thrown
 * away. Asking for a probe takes the key's current generation; an edit that
 * makes the old answer wrong bumps it; the answer is kept only if the
 * generation it took is still the key's.
 */
export class ProbeGenerations {
  private held = new Map<string, number>();

  /** The generation a probe started now belongs to. */
  take(key: string): number {
    return this.held.get(key) ?? 0;
  }

  /** The key was edited: every probe taken before is now stale. */
  bump(key: string): void {
    this.held.set(key, this.take(key) + 1);
  }

  /** Whether an answer from generation `taken` still describes the key. */
  isCurrent(key: string, taken: number): boolean {
    return this.take(key) === taken;
  }
}
