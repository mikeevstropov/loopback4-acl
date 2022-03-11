import {AuthenticateActionProvider, AuthenticateFn, AuthorizeActionProvider, AuthorizeFn} from "../../../";
import {Entity} from "@loopback/repository";
import {MockTokenService} from "./mock-token-service";
import {MockUserService} from "./mock-user-service";

export class MockAuthorizeActionProvider extends AuthorizeActionProvider {

  constructor(readonly result?: boolean) {
    super(
      () => Promise.resolve(undefined),
      () => Promise.resolve(undefined),
      () => Promise.resolve(undefined),
    );
  }

  value(): AuthorizeFn {
    return () => Promise.resolve(this.result ?? false);
  }
}
