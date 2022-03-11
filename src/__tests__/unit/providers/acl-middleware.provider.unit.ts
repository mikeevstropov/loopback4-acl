import {expect, use} from "chai";
import {Next} from "@loopback/context";
import chaiAsPromised from "chai-as-promised";
import {ACLMiddlewareProvider} from "../../..";
import {HttpErrors, MiddlewareContext} from "@loopback/rest";
import {MockAuthorizeActionProvider} from "../fixtures/mock-authorize-action.provider";
import {MockAuthenticateActionProvider} from "../fixtures/mock-authenticate-action.provider";

use(chaiAsPromised);

describe('ACLMiddlewareProvider', () => {
  // TODO: implement
  xit('has rest middleware metadata', async () => {});

  it('throws Forbidden error if authorization fail', async () => {
    const middleware = new ACLMiddlewareProvider(
      (new MockAuthenticateActionProvider()).value(),
      (new MockAuthorizeActionProvider(false)).value(),
    );
    const context = <MiddlewareContext>{};
    const next = <Next>(() => {});
    await expect(middleware.value()(context, next))
      .to.eventually.be.rejectedWith(HttpErrors.Forbidden);
  })
  it('not throws Forbidden error if authorization fail', async () => {
    const middleware = new ACLMiddlewareProvider(
      (new MockAuthenticateActionProvider()).value(),
      (new MockAuthorizeActionProvider(true)).value(),
    );
    const context = <MiddlewareContext>{};
    const next = <Next>(() => {});
    await middleware.value()(context, next)
  })
});
