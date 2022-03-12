# @mikeevstropov/loopback4-acl

A LoopBack 4 component for JWT based authorization support.

## Installation

```shell
npm install --save loopback4-acl-component
```

## Basic use

The following example shows the basic use of `@acl.rules` decorator in class and method levels.

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
    principal: 'admin', // specific role
    permission: ACLPermission.ALLOW,
  }])
  @get('/users/test')
  async test() {
    // ...
  }
}
```

From above the *class level* decorator denies access to all endpoints of
`UserController` for `EVERYONE`. But *method level* decorators allows the `whoAmI` method
for `AUTHENTICATED` and `test` method for
`admin` role.

## How to make it work?

1. Implement your own `User` (required) and `Role` (optional).
2. Implement `ACLUserService` to resolve the session user.
3. Implement `login` method to expose JWT token.
4. Enable `ACLComponent` in your App.

### Implement `ACLUserService`

The User Service is designed to resolve a session user by `TokenPayload` and his
principals (roles) as option.

```ts
export class UserService implements ACLUserService {

  constructor(
    @repository(UserRepository)
    public userRepository : UserRepository,
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
