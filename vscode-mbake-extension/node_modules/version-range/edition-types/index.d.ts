export type Version = string | number;
export type Range = Version | Version[];
/**
 * Check if the version is within the range
 * @param subject The version to check against the range
 * @param range The range to check the version against
 */
export default function withinVersionRange(subject: Version, range: Range): boolean;
//# sourceMappingURL=index.d.ts.map