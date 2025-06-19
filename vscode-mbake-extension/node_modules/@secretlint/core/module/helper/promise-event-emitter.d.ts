export type Listener = (...args: any[]) => void;
export declare class EventEmitter<T extends Listener = Listener> {
    #private;
    on(type: string | Symbol, listener: T): void;
    emit(type: string | Symbol, ...args: any[]): void;
    off(type: string | Symbol, listener: T): void;
    removeAllListeners(): void;
    listenerCount(type: string | Symbol): number;
    listeners(type: string | Symbol): T[];
}
export declare class PromiseEventEmitter {
    private events;
    constructor();
    listenerCount(type: string | Symbol): number;
    on(event: string | Symbol, listener: (...args: any[]) => Promise<void> | void): void;
    emit(event: string | Symbol, ...args: any[]): Promise<void[]>;
}
//# sourceMappingURL=promise-event-emitter.d.ts.map