import {ACLBindings} from '../keys';
import {Request} from '@loopback/rest';
import {ACLTokenService} from '../services';
import {Entity} from '@loopback/repository';
import {ACLAnyPrincipal} from '../decorators';
import {ACLUserService, TokenPayload} from '../services';
import {inject, Setter, Provider} from '@loopback/context';

export type AuthenticateFn = (request: Request) => Promise<Entity | undefined>;

export class AuthenticateActionProvider implements Provider<AuthenticateFn> {
  constructor(
    @inject(ACLBindings.TOKEN_SERVICE)
    public tokenService: ACLTokenService,
    @inject(ACLBindings.USER_SERVICE)
    public userService: ACLUserService,
    @inject.setter(ACLBindings.SESSION_USER)
    readonly setSessionUser: Setter<Entity | undefined>,
    @inject.setter(ACLBindings.SESSION_PRINCIPALS)
    readonly setSessionPrincipals: Setter<ACLAnyPrincipal[]>,
  ) {}

  value(): AuthenticateFn {
    return request => this.action(request);
  }

  async action(request: Request): Promise<Entity | undefined> {
    // Get token.
    let token: string | undefined = request?.headers?.authorization;
    if (!token && request?.headers?.cookie) {
      const matches = request.headers.cookie.match(/Authorization=(.*?)(;|$)/);
      token = matches ? matches[1] : undefined;
    }
    if (!token) return;
    // Decode token.
    let payload: TokenPayload | undefined;
    try {
      payload = await this.tokenService.decode(token)
    } catch(e) {}
    if (!payload) return;
    // Resolve user.
    const user = await this.userService.resolveUser(payload);
    this.setSessionUser(user);
    // Resolve principals.
    if (user) {
      const principals = await this.userService.resolvePrincipals(user);
      this.setSessionPrincipals(principals ?? []);
    }
    // Return user.
    return user;
  }
}
