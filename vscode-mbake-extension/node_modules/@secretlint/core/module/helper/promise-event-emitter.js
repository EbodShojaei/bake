// MIT © 2017 azu
// MIT © 2017 59naga
// https://github.com/59naga/carrack
export class EventEmitter {
    #listeners = new Map();
    on(type, listener) {
        const prevSet = this.#listeners.get(type);
        const listenerSet = prevSet ?? new Set();
        listenerSet?.add(listener);
        this.#listeners.set(type, listenerSet);
    }
    emit(type, ...args) {
        const listenerSet = this.#listeners.get(type);
        if (!listenerSet) {
            return;
        }
        for (const listenerSetElement of listenerSet) {
            listenerSetElement(...args);
        }
    }
    off(type, listener) {
        const listenerSet = this.#listeners.get(type);
        if (!listenerSet) {
            return;
        }
        for (const listenerSetElement of listenerSet) {
            if (listenerSetElement === listener) {
                listenerSet.delete(listener);
            }
        }
    }
    removeAllListeners() {
        this.#listeners.clear();
    }
    listenerCount(type) {
        return this.#listeners.get(type)?.size ?? 0;
    }
    listeners(type) {
        return Array.from(this.#listeners.get(type) ?? []);
    }
}
export class PromiseEventEmitter {
    events;
    constructor() {
        this.events = new EventEmitter();
    }
    listenerCount(type) {
        return this.events.listenerCount(type);
    }
    on(event, listener) {
        return this.events.on(event, listener);
    }
    emit(event, ...args) {
        const promises = [];
        this.events.listeners(event).forEach((listener) => {
            promises.push(listener(...args));
        });
        return Promise.all(promises);
    }
}
//# sourceMappingURL=promise-event-emitter.js.map