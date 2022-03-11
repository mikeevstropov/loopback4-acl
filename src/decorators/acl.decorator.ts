import uniqBy from 'lodash/uniqBy';
import {DecoratorFactory} from '@loopback/core';
import {MetadataInspector} from '@loopback/core';
import {Constructor} from '@loopback/repository';
import {ClassDecoratorFactory} from '@loopback/core';
import {MethodDecoratorFactory} from '@loopback/metadata';
import {ACL_METADATA_CLASS_KEY, ACL_METADATA_METHOD_KEY} from '../keys';

export type ACLMetadata = {
  rules: ACLRule[],
  skip?: boolean,
}

export enum ACLPermission {
  DENY = 'deny',
  ALLOW = 'allow',
}

export enum ACLPrincipal {
  OWNER = '$owner',
  EVERYONE = '$everyone',
  AUTHENTICATED = '$authenticated',
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
export type ACLAnyPrincipal = ACLPrincipal | any;

export type ACLRule = {
  principal: ACLAnyPrincipal;
  permission: ACLPermission;
  method?: string;
}

class ACLClassDecoratorFactory extends ClassDecoratorFactory<ACLRule[]> {}

/**
 * Provides ACL decorator
 * @example `@acl({principal: 'admin', permission: ACLPermission.ALLOW})`
 */
export function acl(spec: ACLMetadata = {rules: []}) {

  return function authenticateDecoratorForClassOrMethod(
    // Class or a prototype
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    target: any,
    method?: string,
    // Use `any` to for `TypedPropertyDescriptor`
    // See https://github.com/loopbackio/loopback-next/pull/2704
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    methodDescriptor?: TypedPropertyDescriptor<any>,
  ) {
    // Method
    if (method && methodDescriptor)
      return MethodDecoratorFactory.createDecorator<ACLMetadata>(
        ACL_METADATA_METHOD_KEY,
        spec,
        {decoratorName: '@acl'},
      )(target, method, methodDescriptor);
    // Class
    if (typeof target === 'function' && !method && !methodDescriptor)
      return ACLClassDecoratorFactory.createDecorator<ACLMetadata>(
        ACL_METADATA_CLASS_KEY,
        spec,
        {decoratorName: '@acl'}
      )(target);
    // Not on a class or method
    throw new Error(
      '@acl cannot be used on a property: ' +
      DecoratorFactory.getTargetName(target, method, methodDescriptor),
    );
  };
}

export namespace acl {
  /**
   * A sugar decorator for rules option.
   * @example `@acl.rules([{principal: 'user', permission: 'deny'}])`
   */
  export const rules = (rules: ACLRule[]) => acl({rules});
  /**
   * A sugar decorator to skip authentication.
   * @example `@acl.skip()`
   */
  export const skip = () => acl({rules: [], skip: true});
}

/**
 * Fetch metadata stored by `@acl` decorator.
 *
 * @param targetClass - Target controller
 * @param methodName - Target method
 */
export function getAclMetadata(
  targetClass: Constructor<{}>,
  methodName: string,
): ACLMetadata | undefined {
  // Get the method level metadata provided by `@acl`.
  const methodMetadata = MetadataInspector.getMethodMetadata<ACLMetadata>(
    ACL_METADATA_METHOD_KEY,
    targetClass.prototype,
    methodName,
  );
  // Get the class level metadata provided by `@acl`.
  const classMetadata = MetadataInspector.getClassMetadata<ACLMetadata>(
    ACL_METADATA_CLASS_KEY,
    targetClass,
  );
  // No @acl metadata is defined.
  if (!methodMetadata && !classMetadata)
    return;
  // Merge by cascading order.
  let rules = [
    ...(classMetadata?.rules ?? []),
    ...(methodMetadata?.rules ?? []),
  ];
  // Define method names for common rules.
  rules = rules.map((rule: ACLRule) => !rule.method
    ? Object.assign({...rule, method: methodName})
    : rule
  );
  // Get current method rules only.
  let methodRules = rules.filter(
    (rule: ACLRule) => rule.method === methodName
  );
  methodRules = uniqBy(methodRules, (rule: ACLRule) => [
    rule.principal,
    rule.permission,
  ].join());

  return {
    skip: false,
    ...classMetadata,
    ...methodMetadata,
    rules: methodRules,
  };
}
