# @mikeevstropov/loopback4-acl

A LoopBack 4 component for JWT based authorization support.

## Installation

```shell
npm install --save loopback4-acl-component
```

## Basic use

The following example shows the basic use of `@acl.rules` decorator in class and method levels.

```ts
import {
  acl,
  ACLPrincipal,
  ACLPermission,
} from "loopback4-acl-component";
import {Entity} from "@loopback/repository";

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

1. Implement your own `User` and `Role`.
2. Implement `ACLUserService` to resolve the user and roles.
3. Implement `login` method to expose JWT token.
4. Enable `ACLComponent` in your App.

### Implement `ACLUserService`

The User Service is designed to resolve a session user by `TokenPayload` and his
principals (roles).

```ts
import {
  TokenPayload,
  ACLUserService,
  ACLAnyPrincipal,
} from '@mikeevstropov/loopback4-acl';
import {UserWithRelations} from '../models';
import {UserRepository} from '../repositories';
import {Entity, repository} from '@loopback/repository';

export class UserService implements ACLUserService {

  constructor(
    @repository(UserRepository)
    public userRepository : UserRepository,
  ) {}

  public async resolveUser(tokenPayload: TokenPayload) {
    return this.userRepository.findById(
      tokenPayload.uid,
      {include: ['roles']},
    );
  }

  public async resolvePrincipals(user: UserWithRelations) {
    return user.roles.map((role: Role) => role.name);
  }
}
```
