import {Entity, property} from "@loopback/repository";

export class MockUser extends Entity {
  @property()
  id: 'uid';
}
