import {AuthenticateActionProvider, AuthenticateFn} from "../../../";
import {Entity} from "@loopback/repository";
import {MockTokenService} from "./mock-token-service";
import {MockUserService} from "./mock-user-service";

export class MockAuthenticateActionProvider extends AuthenticateActionProvider {

  constructor(readonly result?: Entity) {
    super(
      new MockTokenService(),
      new MockUserService(),
      () => undefined,
      () => undefined,
    );
  }

  value(): AuthenticateFn {
    return () => Promise.resolve(this.result);
  }
}
