import graphene
from django.core.exceptions import ValidationError
from graphql_jwt.exceptions import PermissionDenied

from ...account import models as account_models
from ...core import models
from ...core.error_codes import MetaErrorCode
from ...core.permissions import AccountPermissions, get_permissions_for_model
from ..core.mutations import BaseMutation
from ..core.types.common import MetaError
from .types import MetaInput, ObjectWithMetadata


def no_permissions(_info, _object_pk):
    return []


def public_user_permissions(info, user_pk):
    user = account_models.User.objects.filter(pk=user_pk).first()
    if user:
        if info.context.user.pk == user.pk:
            return []
        if user.is_staff:
            return [AccountPermissions.MANAGE_STAFF]
        else:
            return [AccountPermissions.MANAGE_USERS]
    raise PermissionDenied()


PUBLIC_META_CUSTOM_PERMISSION_MAP = {
    "Checkout": no_permissions,
    "Order": no_permissions,
    "User": public_user_permissions,
}


class MetaPermissionOptions(graphene.types.mutation.MutationOptions):
    custom_permission_map = {}


class BaseMetadataMutation(BaseMutation):
    class Meta:
        abstract = True

    class Arguments:
        id = graphene.ID(description="ID of an object to update.", required=True)
        input = MetaInput(
            description="Fields required to update new or stored metadata item.",
            required=True,
        )

    @classmethod
    def __init_subclass_with_meta__(
        cls, arguments=None, custom_permission_map=[], _meta=None, **kwargs,
    ):
        if not _meta:
            _meta = MetaPermissionOptions(cls)
        if not arguments:
            arguments = {}
        fields = {"item": graphene.Field(ObjectWithMetadata)}

        _meta.custom_permission_map = custom_permission_map

        super().__init_subclass_with_meta__(_meta=_meta, **kwargs)
        cls._update_mutation_arguments_and_fields(arguments=arguments, fields=fields)

    @classmethod
    def get_instance(cls, info, **data):
        object_id = data.get("id")
        if object_id:
            try:
                instance = cls.get_node_or_error(info, object_id)
            except ValidationError:
                instance = None
            if instance:
                if issubclass(type(instance), models.ModelWithMetadata):
                    return instance
        raise ValidationError(
            {
                "id": ValidationError(
                    f"Couldn't resolve to a item with meta: {object_id}",
                    code=MetaErrorCode.NOT_FOUND.value,
                )
            }
        )

    @classmethod
    def get_permissions(cls, info, **data):
        object_id = data.get("id")
        if object_id:
            type_name, object_pk = graphene.Node.from_global_id(object_id)
            custom_permission = cls._meta.custom_permission_map.get(type_name)
            if custom_permission:
                return custom_permission(info, object_pk)
            object_type = info.schema.get_type(type_name).graphene_type
            object_model = object_type._meta.model
            return get_permissions_for_model(object_model)
        return []

    @classmethod
    def mutate(cls, root, info, **data):
        permissions = cls.get_permissions(info, **data)
        if not cls.check_permissions(info.context, permissions):
            raise PermissionDenied()
        return super().mutate(root, info, **data)

    @classmethod
    def success_response(cls, instance):
        """Return a success response."""
        return cls(**{"item": instance, "errors": []})


class UpdateMeta(BaseMetadataMutation):
    class Meta:
        description = "Updates metadata for item."
        custom_permission_map = PUBLIC_META_CUSTOM_PERMISSION_MAP
        error_type_class = MetaError
        error_type_field = "meta_errors"

    @classmethod
    def perform_mutation(cls, root, info, **data):
        instance = cls.get_instance(info, **data)
        if instance:
            metadata = data.pop("input")
            stored_data = instance.get_meta(metadata.namespace, metadata.client_name)
            stored_data[metadata.key] = metadata.value
            instance.store_meta(
                namespace=metadata.namespace,
                client=metadata.client_name,
                item=stored_data,
            )
            instance.save()
        return cls.success_response(instance)
