import {expect} from 'chai';
import {createError} from "../../";
import {HttpErrors} from "@loopback/rest";

/**
 * This test suite is for testing utils.
 */
describe('utils', () => {

  it('http error contains specific fields', () => {

    const code = 'ACCESS_FORBIDDEN';
    const message = 'Access forbidden';
    const details = {details: 'Access forbidden'};

    const error = createError(
      HttpErrors.Forbidden,
      code,
      message,
      details,
    );

    expect(error.code).to.equal(code);
    expect(error.message).to.equal(message);
    expect(error.details).to.eql(details);
    expect(error.statusCode).to.equal(403);
  });
});
