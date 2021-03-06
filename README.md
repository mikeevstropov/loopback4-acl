# @mikeevstropov/loopback4-acl

A LoopBack 4 component for JWT based authorization support.

## Features

- Use your own User and Role model without a strict fields scheme.
- Apply access rules to controller and method levels.
- Role based authorization.
- JWT token authentication.

## Installation

```shell
npm install --save @mikeevstropov/loopback4-acl
```
or via `yarn`
```shell
yarn add @mikeevstropov/loopback4-acl
```

## Basic use

The following example shows the basic use of `@acl.rules` decorator in class and method level.

```ts
@acl.rules([{
  principal: ACLPrincipal.EVERYONE,
  permission: ACLPermission.DENY,
}])
export class UserController {

  @acl.rules([{
    principal: ACLPrincipal.AUTHENTICATED,
    permission: ACLPermission.ALLOW,
  }])
  @get('/users/whoAmI')
  async whoAmI(): Promise<User> {
    // ...
  }

  @acl.rules([{
    principal: ACLPrincipal.OWNER,
    permission: ACLPermission.ALLOW,
  }])
  @del('/users/{id}')
  async deleteById(
    @param.path.string('id') id: string,
  ): Promise<void> {
    // ...
  }

  @acl.rules([{
    principal: 'admin', // user role
    permission: ACLPermission.ALLOW,
  }])
  @get('/users/test')
  async test() {
    // ...
  }
}
```
From above:
- The class level decorator `@acl.rules` denies access to all endpoints.
- The method level allows `whoAmI` for `AUTHENTICATED`.
- The method `deleteById` allowed for `OWNER`.
- And `test` allowed for `admin` role.

*Also, you can skip access checking in the method level by a sugar decorator `@acl.skip()`.*

## How to make it work?

1. Create your own `User` and `Role` (optional).
2. Implement `ACLUserService` to resolve the session user.
3. Create `login` method to expose JWT token.
4. Mount `ACLComponent` in your App.

### Implement `ACLUserService`

The User Service is designed to let you resolve an instance
of session user and its roles as you prefer.

```ts
export class UserService implements ACLUserService {

  constructor(
    @repository(UserRepository)
    public userRepository: UserRepository,
  ) {}

  /**
   * Resolve the Session User instance.
   */
  public async resolveUser(tokenPayload: TokenPayload) {
    return this.userRepository.findById(
      tokenPayload.uid,
      {include: ['roles']},
    );
  }

  /**
   * Resolve role-like names of the Session User.
   * 
   * Optional.
   * Do return an empty array if you're not using roles.
   */
  public async resolvePrincipals(user: UserWithRelations) {
    return user.roles.map((role: Role) => role.name);
  }
}
```

### Create `login` method

It doesn't matter how you get the User instance in `login`
method, but you need to generate JWT token from its `id`.

```ts
export class UserController {

  constructor(
    @repository(UserRepository)
    public userRepository: UserRepository,
    @inject(ACLBindings.TOKEN_SERVICE)
    private tokenService: ACLTokenService,
  ) {}

  // ...

  async login(
    @requestBody(LoginRequestBody)
    loginParameters: LoginParameters,
  ): Promise<LoginResponse> {

    // ...

    const user = await this.userRepository.findOne({
      where: {username, password}
    });

    if (!user)
      throw HttpErrors.Forbidden();

    const token = await this.tokenService.encode({
      uid: user.id,
    });

    return token;
  }
}
```

### Mount `ACLComponent`

Finally, bind your own `ACLUserService` and mount
the `ACLComponent` to your App in *application.ts*

```ts
export class App extends BootMixin() {
  
  // ...

  this.bind(ACLBindings.USER_SERVICE).toClass(UserService);
  this.component(ACLComponent);
}
```

## Tests

run `npm test` from the root folder.

## License

MIT
