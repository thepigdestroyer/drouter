/** Error with an HTTP status, thrown by node logic and mapped to JSON responses by the routes. */
export class SimError extends Error {
  readonly status: number;

  constructor(status: number, message: string) {
    super(message);
    this.name = "SimError";
    this.status = status;
  }
}
