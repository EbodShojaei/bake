export class SecretLintProfiler {
    perf;
    entries = [];
    measures = [];
    executionPromises = [];
    constructor(options) {
        this.perf = options.perf;
        const pattern = /(.*?)::end(\|\|.*)?/;
        const observer = new options.PerformanceObserver((items) => {
            const entries = items.getEntries();
            entries.forEach((entry) => {
                if (entry.entryType === "mark") {
                    const match = entry.name.match(pattern);
                    const endIdentifier = match ? match[1] : undefined;
                    const suffix = match && match[2] ? match[2] : "";
                    // if mark already {mark}::start, measure start to end
                    if (endIdentifier) {
                        const startIdentifier = `${endIdentifier}::start`;
                        this.entries.find((savedEntry) => {
                            return savedEntry.name === startIdentifier;
                        });
                        // create measure
                        if (startIdentifier) {
                            // FIXME: avoid ERR_INVALID_PERFORMANCE_MARK error
                            this.executionPromises.push(Promise.resolve().then(() => {
                                this.perf.measure(endIdentifier + suffix, `${endIdentifier}::start${suffix}`, `${endIdentifier}::end${suffix}`);
                            }));
                        }
                    }
                    this.entries.push(entry);
                }
                else if (entry.entryType === "measure") {
                    this.measures.push(entry);
                }
            });
        });
        observer.observe({ entryTypes: ["mark", "measure"] });
    }
    mark(marker) {
        if ("id" in marker) {
            this.perf.mark(`${marker.type}||${marker.id}`);
        }
        else {
            this.perf.mark(marker.type);
        }
    }
    waifForExecutionPromises = () => {
        return Promise.all(this.executionPromises).finally(() => {
            this.executionPromises.length = 0;
        });
    };
    async getEntries() {
        await this.waifForExecutionPromises();
        return this.entries;
    }
    async getMeasures() {
        await this.waifForExecutionPromises();
        return this.measures;
    }
}
//# sourceMappingURL=index.js.map