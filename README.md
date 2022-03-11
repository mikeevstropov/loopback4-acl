# @mikeevstropov/loopback4-acl

A LoopBack 4 component for Permission based authorization support.

## Installation

```shell
npm install --save loopback4-acl-component
```

## Basic use

The following example shows the basic use of `@acl.rules` decorator in class and method levels.

```ts
import {Entity} from "@loopback/repository";
import {acl, ACLPrincipal, ACLPermission} from "loopback4-acl-component";

@acl.rules([{
  principal: ACLPrincipal.EVERYONE,
  permission: ACLPermission.DENY,
}])
export class UserController {

  @acl.rules([{
    principal: ACLCommonPrincipal.AUTHENTICATED,
    permission: ACLPermission.ALLOW,
  }])
  @get('/users/whoAmI')
  async whoAmI(): Promise<User> {
    // ...
  }
}
```
