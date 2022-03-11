import {Entity} from '@loopback/repository';
import {ACLAnyPrincipal} from '../decorators';
import {TokenPayload} from './acl-token.service';

export interface ACLUserService {

  /**
   * Resolve the User instance.
   */
  resolveUser(tokenPayload: TokenPayload): Promise<Entity | undefined>;

  /**
   * Resolve role-like names of the User.
   */
  resolvePrincipals(user: Entity): Promise<ACLAnyPrincipal[]>;
}
