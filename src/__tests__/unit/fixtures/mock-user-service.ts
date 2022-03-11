import {
  TokenPayload,
  ACLUserService,
  ACLAnyPrincipal,
} from "../../../";
import {MockUser} from "./mock-user";
import {Entity} from "@loopback/repository";

export const mockUser = new MockUser();
export const mockPrincipals = ['user-role', 'manager-role'];

export class MockUserService implements ACLUserService {

  constructor(readonly noUser?: boolean) {}

  public async resolveUser(tokenPayload: TokenPayload): Promise<Entity | undefined> {
    return this.noUser ? undefined : mockUser;
  }

  public async resolvePrincipals(user: Entity): Promise<ACLAnyPrincipal[]> {
    return mockPrincipals;
  }
}
