// Fixture for dy-derived-slot-name (hub#495 rule C11).

declare const SITE_STORAGE_ROOT: string;
declare function isSiteSlug(value: unknown): value is string;

// The one helper may build the name: the rule excludes it.
export function derivedSlotNameFor(liveSlug: string, slot: "staging" | "dev1" | "dev2" | "dev3"): string {
  if (!isSiteSlug(liveSlug)) {
    throw new RangeError("not a site slug");
  }
  // ok: dy-derived-slot-name
  return `${liveSlug}-${slot}`;
}

export function handBuilt(slug: string, n: number, prefix: string): string[] {
  return [
    // ruleid: dy-derived-slot-name
    `${SITE_STORAGE_ROOT}/platform/${slug}-staging`,
    // ruleid: dy-derived-slot-name
    `/platform/${slug}-staging/wp-config-real.php`,
    // ruleid: dy-derived-slot-name
    `${slug}-dev${n}`,
    // ruleid: dy-derived-slot-name
    `${slug}-dev2`,
    // ruleid: dy-derived-slot-name
    `${SITE_STORAGE_ROOT}/platform/${slug}-${prefix}`,
    // ruleid: dy-derived-slot-name
    `sg-${slug}`,
    // ruleid: dy-derived-slot-name
    slug + "-staging",
    // ruleid: dy-derived-slot-name
    slug + "-dev" + n,
    // ruleid: dy-derived-slot-name
    "sg-" + slug,
    // ruleid: dy-derived-slot-name
    'sg-' + slug,
  ];
}

export function throughTheHelper(slug: string, liveDatabaseName: string): string[] {
  return [
    // ok: dy-derived-slot-name
    `${SITE_STORAGE_ROOT}/platform/${derivedSlotNameFor(slug, "staging")}`,
    // ok: dy-derived-slot-name
    `${SITE_STORAGE_ROOT}/platform/${slug}`,
    // ok: dy-derived-slot-name
    `${SITE_STORAGE_ROOT}/sites/${slug}/staging`,
    // A DB name with `_staging` is another name space (MariaDB), not a slot name.
    // ok: dy-derived-slot-name
    `${liveDatabaseName}_staging`,
    // A fixed string is not derived from a slug.
    // ok: dy-derived-slot-name
    "--no-staging",
    // ok: dy-derived-slot-name
    `msg-${slug}`,
  ];
}
