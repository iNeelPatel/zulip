from django.core.exceptions import ValidationError
from django.http import HttpRequest, HttpResponse
from django.utils.translation import gettext as _
from django.views.decorators.csrf import csrf_exempt

from zerver.actions.realm_domains import (
    do_add_realm_domain,
    do_change_realm_domain,
    do_remove_realm_domain,
)
from zerver.decorator import require_realm_owner
from zerver.lib.domains import validate_domain
from zerver.lib.exceptions import JsonableError
from zerver.lib.request import REQ, has_request_variables
from zerver.lib.response import json_success
from zerver.lib.validator import check_bool
from zerver.models import RealmDomain, UserProfile
from zerver.models.realms import get_realm_domains
from zerver.views.registration import (
    create_realm_custom
)

def list_realm_domains(request: HttpRequest, user_profile: UserProfile) -> HttpResponse:
    domains = get_realm_domains(user_profile.realm)
    return json_success(request, data={"domains": domains})

@csrf_exempt
def createRealmApi(request: HttpRequest) -> HttpResponse:
    if request.method == "POST":
        api_key = request.POST.get("api_key")
        if api_key == "123443123":

            # get all details from body

            email = request.POST.get("email")
            realm_name = request.POST.get("realm_name")
            realm_type = request.POST.get("realm_type")
            realm_subdomain = request.POST.get("realm_subdomain")
            full_name = request.POST.get("full_name")
            password = request.POST.get("password")

            activation_url = create_realm_custom(
                email,
                realm_name,
                realm_subdomain,
                realm_type,
                "en",
                full_name,
                password,
            )

            # key_record.delete()

            return json_success(request, data={"activation_url": activation_url})
        else:
            raise JsonableError(_("API key is not valid").format(error="API key is not valid"))

@require_realm_owner
@has_request_variables
def create_realm_domain(
    request: HttpRequest,
    user_profile: UserProfile,
    domain: str = REQ(),
    allow_subdomains: bool = REQ(json_validator=check_bool),
) -> HttpResponse:
    domain = domain.strip().lower()
    try:
        validate_domain(domain)
    except ValidationError as e:
        raise JsonableError(_("Invalid domain: {error}").format(error=e.messages[0]))
    if RealmDomain.objects.filter(realm=user_profile.realm, domain=domain).exists():
        raise JsonableError(
            _("The domain {domain} is already a part of your organization.").format(domain=domain)
        )
    realm_domain = do_add_realm_domain(
        user_profile.realm, domain, allow_subdomains, acting_user=user_profile
    )
    return json_success(request, data={"new_domain": [realm_domain.id, realm_domain.domain]})


@require_realm_owner
@has_request_variables
def patch_realm_domain(
    request: HttpRequest,
    user_profile: UserProfile,
    domain: str,
    allow_subdomains: bool = REQ(json_validator=check_bool),
) -> HttpResponse:
    try:
        realm_domain = RealmDomain.objects.get(realm=user_profile.realm, domain=domain)
        do_change_realm_domain(realm_domain, allow_subdomains, acting_user=user_profile)
    except RealmDomain.DoesNotExist:
        raise JsonableError(_("No entry found for domain {domain}.").format(domain=domain))
    return json_success(request)


@require_realm_owner
@has_request_variables
def delete_realm_domain(
    request: HttpRequest, user_profile: UserProfile, domain: str
) -> HttpResponse:
    try:
        realm_domain = RealmDomain.objects.get(realm=user_profile.realm, domain=domain)
        do_remove_realm_domain(realm_domain, acting_user=user_profile)
    except RealmDomain.DoesNotExist:
        raise JsonableError(_("No entry found for domain {domain}.").format(domain=domain))
    return json_success(request)
