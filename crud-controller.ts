import {
  Body,
  ConflictException,
  Delete,
  Get,
  Param,
  Post,
  Put,
  Query,
  Req,
  UnauthorizedException,
  UnprocessableEntityException,
  UseGuards,
} from '@nestjs/common';
import { Brackets, Repository } from 'typeorm';
import { ContentEntity } from '../entities/content.entity';
import { ContentPermissionsGuard } from '../guards/content-permissions.guard';
import { ContentPermissionHelper, ContentPermissionsKeys } from '../../roles-and-permissions/misc/content-permission-helper';
import { User } from '../../users/decorators/user.decorator';
import { UserEntity } from '../../users/entities/user.entity';
import { RolesAndPermissionsService } from '../../roles-and-permissions/services/roles-and-permissions.service';
import { ContentEntityNotFoundGuard } from '../guards/content-entity-not-found.guard';
import { ContentViewUnpublishedPermissionsGuard } from '../guards/content-view-unpublished-permission.guard';
import { ContentEntityParam } from '../decorators/content-entity-param.decorator';
import { PaymentCardEntity } from '../../../payments/entities/payment-card.entity';

export class CrudController {

  constructor(
    protected rolesAndPermissions: RolesAndPermissionsService,
    protected contentPermissionsHelper: ContentPermissionHelper,
  ) {}

  protected repository: Repository<ContentEntity>;

  @Get('')
  async loadContentEntities(@User() user: UserEntity, @Query() query) {
    const builder = await this.getQueryBuilder(user, query);
    return builder.getMany();
  }

  @Get('total')
  async countContentEntities(@User() user: UserEntity, @Query() query) {
    const builder = await this.getQueryBuilder(user, query);
    const total = await builder.getCount();
    return { total };
  }

  @Get(':id')
  @UseGuards(ContentViewUnpublishedPermissionsGuard)
  @UseGuards(ContentPermissionsGuard(isOwner => {
    if (isOwner) {
      return ContentPermissionsKeys[ContentPermissionsKeys.ContentViewOwn];
    } else {
      return ContentPermissionsKeys[ContentPermissionsKeys.ContentViewAll];
    }
  }))
  @UseGuards(ContentEntityNotFoundGuard)
  loadContentEntity(@ContentEntityParam() entity: ContentEntity) {
    return entity;
  }

  @Post('')
  @UseGuards(ContentPermissionsGuard(isOwner => ContentPermissionsKeys[ContentPermissionsKeys.ContentAdd]))
  async createContentEntity(@Body() entity: ContentEntity, @User() user: UserEntity) {
    if (user.isAuthorized()) {
      entity.authorId = user.id;
      entity.moderatorId = user.id;
    } else {
      entity.authorId = null;
      entity.moderatorId = null;
    }
    const validateResult = true;
    if (validateResult === true) {
      try {
        return await this.repository.save(entity);
      } catch (e) {
        if (e.code === 'ER_DUP_ENTRY') {
          throw new ConflictException('Duplicate entity. Please, check unique fields');
        } else {
          console.log(new Date(), e);
          throw new UnprocessableEntityException('Something went wrong. Please try later or contact us');
        }
      }
    } else {
      throw new UnprocessableEntityException(validateResult);
    }
  }

  @Put(':id')
  @UseGuards(ContentPermissionsGuard(isOwner => {
    if (isOwner) {
      return ContentPermissionsKeys[ContentPermissionsKeys.ContentEditOwn];
    } else {
      return ContentPermissionsKeys[ContentPermissionsKeys.ContentEdit];
    }
  }))
  @UseGuards(ContentEntityNotFoundGuard)
  async updateContentEntity(
    @User() user: UserEntity,
    @ContentEntityParam() currentEntity: ContentEntity,
    @Body() newEntity: ContentEntity,
  ) {
    newEntity.id = currentEntity.id;
    newEntity.authorId = currentEntity.authorId;
    newEntity.moderatorId = user.id;
    Object.assign(currentEntity, newEntity);
    const validateResult = true;
    if (validateResult === true) {
      try {
        const test =  await this.repository.save(currentEntity);
        return test;
      } catch (e) {
        console.error(e);
      }
    } else {
      throw new UnprocessableEntityException(validateResult);
    }
  }

  @Delete(':id')
  @UseGuards(ContentPermissionsGuard(isOwner => {
    if (isOwner) {
      return ContentPermissionsKeys[ContentPermissionsKeys.ContentRemoveOwn];
    } else {
      return ContentPermissionsKeys[ContentPermissionsKeys.ContentRemove];
    }
  }))
  @UseGuards(ContentEntityNotFoundGuard)
  async deleteContentEntity(@Param('id') id: number) {
    const entity = await this.repository.findOne({ id });
    return await this.repository.remove(entity);
  }

  async getWhereRestrictionsByPermissions(user: UserEntity) {

    const entityName = (this.constructor as any).entityFn.name;
    const entityFn = (this.constructor as any).entityFn;

    const permissions: {
      viewAll?: boolean,
      viewUnpublished?: boolean,
      viewOwn?: boolean,
    } = {};

    permissions.viewAll = await this.checkPermissionGranted(
      ContentPermissionsKeys.ContentViewAll,
      entityName,
      user,
    );

    permissions.viewUnpublished = await this.checkPermissionGranted(
      ContentPermissionsKeys.ContentViewUnpublished,
      entityName,
      user,
    );

    permissions.viewOwn = await this.checkPermissionGranted(
      ContentPermissionsKeys.ContentViewOwn,
      entityName,
      user,
    );

    if (permissions.viewAll || permissions.viewOwn) {
      const where: Partial<ContentEntity> = {};
      if (permissions.viewAll) {
        if (!permissions.viewUnpublished) {
          where.isPublished = true;
          if (permissions.viewOwn) {
            entityFn.ownerFields.forEach((field: string) => {
              where[field] = user.id;
            });
          }
        }
      } else {
        entityFn.ownerFields.forEach((field: string) => {
          where[field] = user.id;
        });
      }
      return where;
    } else {
      return false;
    }
  }

  private async checkPermissionGranted(key: ContentPermissionsKeys, entityName: string, user: UserEntity) {
    const permission = await this.rolesAndPermissions
      .getPermissionByKey(
        this.contentPermissionsHelper
          .getKeyByContentName(
            ContentPermissionsKeys[key],
            entityName,
          ),
      );
    return await this.rolesAndPermissions
      .checkPermissionByRoles(permission, user.roles);
  }

  protected async getQueryBuilder(user: UserEntity, query: any, skipPermission = false) {
    const extraWhere = await this.getWhereRestrictionsByPermissions(user);
    if (extraWhere === false && !skipPermission) {
      throw new UnauthorizedException();
    }
    const builder = this.repository
      .createQueryBuilder('entity');

    const ownerFields = (this.constructor as any).entityFn.ownerFields as string[];
    const hasOwnerFields = ownerFields.reduce((res, field) => {
      return res && typeof extraWhere[field] !== 'undefined';
    }, true);
    if (extraWhere) {
      builder.where(new Brackets(sqb1 => {
        if (hasOwnerFields) {
          sqb1.where(new Brackets(sqb2 => {
            ownerFields.forEach((field, i) => {
              const parts: string[] = field.split('.');
              parts.pop();
              parts.reduce((res, part, idx) => {
                res += `.${part}`;
                builder.leftJoin(res, res);
                return res;
              }, 'entity');
              if (i) {
                sqb2.orWhere(`entity.${field} = :${field}`, extraWhere);
              } else {
                sqb2.where(`entity.${field} = :${field}`, extraWhere);
              }
            });
            return sqb2;
          }));
          if (extraWhere.isPublished) {
            sqb1.orWhere('entity.isPublished = :isPublished', extraWhere);
          }
        } else {
          if (extraWhere.isPublished) {
            sqb1.where('entity.isPublished = :isPublished', extraWhere);
          }
        }
      }));
    }
    if (query.orderBy && query.order) {
      builder.addOrderBy(`entity.${query.orderBy}`, query.order.toUpperCase() as any);
    }
    if (query.limit) {
      const maxLimit = 100; // 100
      const queryLimit = parseInt(query.limit,  10);
      if (queryLimit > maxLimit) {
        console.warn(`Limit was overriden due to more than max limit (${maxLimit})`);
        query.limit = maxLimit;
      } else {
        query.limit = queryLimit;
      }
      query.page = query.page || 0;
    } else {
      query.limit = 25;
      query.page = 0;
    }
    builder.take(query.limit);
    builder.skip(query.offset || query.limit * query.page);
    delete query.limit;
    delete query.page;
    delete query.orderBy;
    delete query.order;
    delete query.offset;
    const queryKeys = Object.keys(query);
    queryKeys.forEach(key => {
      if (Array.isArray(query[key])) {
        builder.andWhere(`entity.${key} IN(:...${key})`, query);
      } else {
        builder.andWhere(`entity.${key} = :${key}`, query);
      }
    });
    return builder;
  }

}
