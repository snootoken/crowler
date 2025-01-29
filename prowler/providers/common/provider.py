import importlib
import pkgutil
import sys
from abc import ABC, abstractmethod
from argparse import Namespace
from importlib import import_module
from typing import Any, Optional

from prowler.config.config import load_and_validate_config_file
from prowler.lib.logger import logger
from prowler.lib.mutelist.mutelist import Mutelist

providers_path = "prowler.providers"


class Provider(ABC):
    """
    Abstract base class for cloud providers like AWS, Azure, GCP, Kubernetes, Microsoft 365.

    Attributes:
        _type (str): The provider type (aws, azure, gcp, etc.).
        _session (Any): The provider session object.
        mutelist (Mutelist): The mutelist for the provider.
        audit_config (dict): Configuration settings for the provider.
    """

    _global: Optional["Provider"] = None
    mutelist: Mutelist

    @property
    @abstractmethod
    def type(self) -> str:
        """Returns the type of the provider (e.g., aws, azure, gcp, kubernetes)."""
        raise NotImplementedError()

    @property
    @abstractmethod
    def session(self) -> Any:
        """Returns the provider's session."""
        raise NotImplementedError()

    @abstractmethod
    def setup_session(self) -> Any:
        """Sets up a session for the provider (e.g., Boto3, Azure SDK)."""
        raise NotImplementedError()

    @abstractmethod
    def test_connection(self) -> bool:
        """Validates provider credentials (e.g., AWS STS, Azure AD, GCP IAM)."""
        raise NotImplementedError()

    def print_credentials(self) -> None:
        """Displays provider credentials (if applicable)."""
        raise NotImplementedError()

    @staticmethod
    def get_global_provider() -> "Provider":
        """Returns the globally initialized provider instance."""
        return Provider._global

    @staticmethod
    def set_global_provider(global_provider: "Provider") -> None:
        """Sets the globally initialized provider instance."""
        Provider._global = global_provider

    @staticmethod
    def init_global_provider(arguments: Namespace) -> None:
        """
        Initializes a provider dynamically based on CLI arguments.
        Supports AWS, Azure, GCP, Kubernetes, Microsoft 365.

        Args:
            arguments (Namespace): Parsed command-line arguments.
        """
        try:
            provider_class_path = (
                f"{providers_path}.{arguments.provider}.{arguments.provider}_provider"
            )
            provider_class_name = f"{arguments.provider.capitalize()}Provider"
            provider_class = getattr(import_module(provider_class_path), provider_class_name)

            # Load config for provider
            fixer_config = load_and_validate_config_file(arguments.provider, arguments.fixer_config)

            # Prevent re-initialization
            if isinstance(Provider._global, provider_class):
                return

            if arguments.provider.lower() == "aws":
                provider_class(
                    retries_max_attempts=arguments.aws_retries_max_attempts,
                    role_arn=arguments.role,
                    session_duration=arguments.session_duration,
                    external_id=arguments.external_id,
                    role_session_name=arguments.role_session_name,
                    mfa=arguments.mfa,
                    profile=arguments.profile,
                    regions=set(arguments.region) if arguments.region else None,
                    organizations_role_arn=arguments.organizations_role,
                    scan_unused_services=arguments.scan_unused_services,
                    resource_tags=arguments.resource_tag,
                    resource_arn=arguments.resource_arn,
                    config_path=arguments.config_file,
                    mutelist_path=arguments.mutelist_file,
                    fixer_config=fixer_config,
                )

            elif arguments.provider.lower() == "azure":
                provider_class(
                    az_cli_auth=arguments.az_cli_auth,
                    sp_env_auth=arguments.sp_env_auth,
                    browser_auth=arguments.browser_auth,
                    managed_identity_auth=arguments.managed_identity_auth,
                    tenant_id=arguments.tenant_id,
                    region=arguments.azure_region,
                    subscription_ids=arguments.subscription_id,
                    config_path=arguments.config_file,
                    mutelist_path=arguments.mutelist_file,
                    fixer_config=fixer_config,
                )

            elif arguments.provider.lower() == "gcp":
                provider_class(
                    organization_id=arguments.organization_id,
                    project_ids=arguments.project_id,
                    excluded_project_ids=arguments.excluded_project_id,
                    credentials_file=arguments.credentials_file,
                    impersonate_service_account=arguments.impersonate_service_account,
                    list_project_ids=arguments.list_project_id,
                    config_path=arguments.config_file,
                    mutelist_path=arguments.mutelist_file,
                    fixer_config=fixer_config,
                )

            elif arguments.provider.lower() == "kubernetes":
                provider_class(
                    kubeconfig_file=arguments.kubeconfig_file,
                    context=arguments.context,
                    namespace=arguments.namespace,
                    config_path=arguments.config_file,
                    mutelist_path=arguments.mutelist_file,
                    fixer_config=fixer_config,
                )

            elif arguments.provider.lower() == "microsoft365":
                provider_class(
                    region=arguments.region,
                    config_path=arguments.config_file,
                    mutelist_path=arguments.mutelist_file,
                    sp_env_auth=arguments.sp_env_auth,
                    az_cli_auth=arguments.az_cli_auth,
                    browser_auth=arguments.browser_auth,
                    tenant_id=arguments.tenant_id,
                    fixer_config=fixer_config,
                )

        except TypeError as error:
            logger.critical(f"TypeError[{error.__traceback__.tb_lineno}]: {error}")
            sys.exit(1)
        except Exception as error:
            logger.critical(f"Error[{error.__traceback__.tb_lineno}]: {error}")
            sys.exit(1)

    @staticmethod
    def get_available_providers() -> list[str]:
        """Returns a list of available cloud providers."""
        providers = []
        prowler_providers = importlib.import_module(providers_path)
        for _, provider, ispkg in pkgutil.iter_modules(prowler_providers.__path__):
            if provider != "common" and ispkg:
                providers.append(provider)
        return providers

    @staticmethod
    def update_provider_config(audit_config: dict, variable: str, value: str):
        """Updates provider-specific configuration dynamically."""
        try:
            if audit_config and variable in audit_config:
                audit_config[variable] = value
            return audit_config
        except Exception as error:
            logger.error(f"Config Update Error[{error.__traceback__.tb_lineno}]: {error}")


# 🔹 **Example Usage**
if __name__ == "__main__":
    from argparse import ArgumentParser

    parser = ArgumentParser(description="Cloud Provider Connection Tester")
    parser.add_argument("--provider", choices=["aws", "azure", "gcp", "kubernetes", "microsoft365"], required=True)
    parser.add_argument("--profile", type=str, help="AWS Profile")
    parser.add_argument("--tenant_id", type=str, help="Azure Tenant ID")
    parser.add_argument("--credentials_file", type=str, help="GCP Credentials File")
    
    args = parser.parse_args()
    
    print("\n🔍 Initializing Provider...")
    Provider.init_global_provider(args)

    global_provider = Provider.get_global_provider()
    
    print("\n🔍 Testing Connection...")
    if global_provider.test_connection():
        print("✅ Connection Successful!")
    else:
        print("❌ Connection Failed!")
