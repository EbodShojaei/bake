export type runConfigCreatorOptions = {
    cwd: string;
};
export declare const runConfigCreator: (options: runConfigCreatorOptions) => Promise<{
    exitStatus: number;
    stdout: string | null;
    stderr: Error | null;
}>;
//# sourceMappingURL=create-secretlintrc.d.ts.map