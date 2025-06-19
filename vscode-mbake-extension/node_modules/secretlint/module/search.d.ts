export type SearchFilesOptions = {
    cwd: string;
    ignoreFilePath?: string;
};
/**
 * globby wrapper that support ignore options
 * @param patterns
 * @param options
 */
export declare const searchFiles: (patterns: string[], options: SearchFilesOptions) => Promise<{
    ok: boolean;
    items: string[];
}>;
//# sourceMappingURL=search.d.ts.map