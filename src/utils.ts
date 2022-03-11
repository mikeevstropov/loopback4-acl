import {HttpErrorConstructor} from 'http-errors';

export function createError(
  constructor: HttpErrorConstructor,
  code: string,
  message: string,
  details?: object | null,
) {
  return Object.assign(new constructor(message), {code, message, details});
}
