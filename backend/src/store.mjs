import { mkdir, readFile, rename, unlink, writeFile } from 'node:fs/promises';
import { dirname } from 'node:path';
import { randomUUID } from 'node:crypto';

const emptyState = () => ({ schemaVersion: 1, reports: [], watchlist: [], notificationEvents: [] });

export class Store {
  #state;
  #file;
  #pending = Promise.resolve();

  constructor(state = emptyState(), file = null) {
    if (state?.schemaVersion !== 1 || !Array.isArray(state.reports)) {
      throw new Error('Unsupported or corrupt data file');
    }
    this.#state = state;
    this.#file = file;
  }

  static async open(file = null) {
    if (!file) return new Store();
    try {
      const state = JSON.parse(await readFile(file, 'utf8'));
      return new Store(state, file);
    } catch (error) {
      if (error.code === 'ENOENT') return new Store(emptyState(), file);
      throw error;
    }
  }

  read(fn) {
    return structuredClone(fn(this.#state));
  }

  update(fn) {
    const operation = this.#pending.then(async () => {
      const next = structuredClone(this.#state);
      const result = fn(next);
      if (this.#file) await this.#write(next);
      this.#state = next;
      return structuredClone(result);
    });
    this.#pending = operation.catch(() => {});
    return operation;
  }

  async #write(state) {
    await mkdir(dirname(this.#file), { recursive: true });
    const temporary = `${this.#file}.${randomUUID()}.tmp`;
    try {
      await writeFile(temporary, `${JSON.stringify(state, null, 2)}\n`, { flag: 'wx', mode: 0o600 });
      await rename(temporary, this.#file);
    } catch (error) {
      await unlink(temporary).catch(() => {});
      throw error;
    }
  }
}
