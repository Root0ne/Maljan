/**
 * A stable identity for each stage card.
 *
 * A card keyed by its stage's key was remounted on every keystroke in the key
 * box, and one keyed by its place took another card's local state (condition
 * problems, focus) when a stage was removed or moved. The identity is a uid
 * held for the stage object, handed to the object that replaces it when an
 * edit, a rename or a removal rebuilds it, so it survives all three and a
 * move (which reuses the objects).
 */
const uids = new WeakMap<object, string>();
let counter = 0;

/** The uid of a stage object, assigned the first time it is asked for. */
export function uidOf(stage: object): string {
  let uid = uids.get(stage);
  if (uid === undefined) {
    counter += 1;
    uid = `stage-${counter}`;
    uids.set(stage, uid);
  }
  return uid;
}

/** `to` stands for the same stage `from` did: it takes over its uid. */
export function carryUid<T extends object>(from: object, to: T): T {
  uids.set(to, uidOf(from));
  return to;
}
