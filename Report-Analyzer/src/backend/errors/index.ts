

export class BadRequest extends Error {
  constructor(msg: string) {
    super(msg)
  }
}


export class InternalServerError extends Error {
  constructor(msg: string) {
    super(msg)
  }
}
