/**
 * True positive — sequential-counter edge case.
 */

export class Server {
  private _progressCounter = 0;

  startWork(): number {
    const progressToken = ++this._progressCounter;
    return progressToken;
  }
}
