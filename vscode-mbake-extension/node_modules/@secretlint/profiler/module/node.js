import { SecretLintProfiler } from "./index.js";
import perf_hooks from "node:perf_hooks";
export { SecretLintProfiler };
class NullPerformanceObserver {
    disconnect() { }
    observe(_options) { }
}
export const secretLintProfiler = new SecretLintProfiler({
    perf: perf_hooks.performance,
    PerformanceObserver: perf_hooks.PerformanceObserver ? perf_hooks.PerformanceObserver : NullPerformanceObserver,
});
//# sourceMappingURL=node.js.map