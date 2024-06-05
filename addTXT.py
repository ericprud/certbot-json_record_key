import logging
from typing import Callable
from typing import Mapping
logger = logging.getLogger(__name__)

import abc
from typing import Any
from typing import Optional
import argparse
from typing import Dict
import enum
from typing import List
from unittest import mock
import os
import configobj
from certbot import errors

import pdb, traceback, sys

import json
import requests
from urllib.error import HTTPError

def validate_file(filename: str) -> None:
    """Ensure that the specified file exists."""

    if not os.path.exists(filename):
        raise errors.PluginError('File not found: {0}'.format(filename))

    if os.path.isdir(filename):
        raise errors.PluginError('Path is a directory: {0}'.format(filename))

def validate_file_permissions(filename):

    validate_file(filename)

    # if filesystem.has_world_permissions(filename):
    #     logger.warning('Unsafe permissions on credentials configuration file: %s', filename)


class CredentialsConfiguration:
    """Represents a user-supplied filed which stores API credentials."""

    def __init__(self, filename: str, mapper: Callable[[str], str] = lambda x: x) -> None:
        """
        :param str filename: A path to the configuration file.
        :param callable mapper: A transformation to apply to configuration key names
        :raises errors.PluginError: If the file does not exist or is not a valid format.
        """
        validate_file_permissions(filename)

        try:
            self.confobj = configobj.ConfigObj(filename)
        except configobj.ConfigObjError as e:
            logger.debug(
                "Error parsing credentials configuration '%s': %s",
                filename,
                e,
                exc_info=True
            )
            raise errors.PluginError(
                "Error parsing credentials configuration '{}': {}".format(
                    filename,
                    e
                )
            )

        self.mapper = mapper

    def require(self, required_variables: Mapping[str, str]) -> None:
        """Ensures that the supplied set of variables are all present in the file.

        :param dict required_variables: Map of variable which must be present to error to display.
        :raises errors.PluginError: If one or more are missing.
        """
        messages = []

        for var in required_variables:
            if not self._has(var):
                messages.append('Property "{0}" not found (should be {1}).'
                                .format(self.mapper(var), required_variables[var]))
            elif not self._get(var):
                messages.append('Property "{0}" not set (should be {1}).'
                                .format(self.mapper(var), required_variables[var]))

        if messages:
            raise errors.PluginError(
                'Missing {0} in credentials configuration file {1}:\n * {2}'.format(
                        'property' if len(messages) == 1 else 'properties',
                        self.confobj.filename,
                        '\n * '.join(messages)
                    )
            )

    def conf(self, var: str) -> Optional[str]:
        """Find a configuration value for variable `var`, as transformed by `mapper`.

        :param str var: The variable to get.
        :returns: The value of the variable, if it exists.
        :rtype: str or None
        """

        return self._get(var)

    def _has(self, var: str) -> bool:
        return self.mapper(var) in self.confobj

    def _get(self, var: str) -> Optional[str]:
        return self.confobj.get(self.mapper(var))

class ArgumentSource(enum.Enum):
    """Enum for describing where a configuration argument was set."""

    COMMAND_LINE = enum.auto()
    """Argument was specified on the command line"""
    CONFIG_FILE = enum.auto()
    """Argument was specified in a .ini config file"""
    DEFAULT = enum.auto()
    """Argument was not set by the user, and was assigned its default value"""
    ENV_VAR = enum.auto()
    """Argument was specified in an environment variable"""
    RUNTIME = enum.auto()
    """Argument was set at runtime by certbot"""

class NamespaceConfig:
    """Configuration wrapper around :class:`argparse.Namespace`.

    Please note that the following attributes are dynamically resolved using
    :attr:`~certbot.configuration.NamespaceConfig.work_dir` and relative
    paths defined in :py:mod:`certbot._internal.constants`:

      - `accounts_dir`
      - `csr_dir`
      - `in_progress_dir`
      - `key_dir`
      - `temp_checkpoint_dir`

    And the following paths are dynamically resolved using
    :attr:`~certbot.configuration.NamespaceConfig.config_dir` and relative
    paths defined in :py:mod:`certbot._internal.constants`:

      - `default_archive_dir`
      - `live_dir`
      - `renewal_configs_dir`

    :ivar namespace: Namespace typically produced by
        :meth:`argparse.ArgumentParser.parse_args`.
    :type namespace: :class:`argparse.Namespace`

    """

    def __init__(self, namespace: argparse.Namespace) -> None:
        self.namespace: argparse.Namespace
        # Avoid recursion loop because of the delegation defined in __setattr__
        object.__setattr__(self, 'namespace', namespace)
        object.__setattr__(self, '_argument_sources', None)
        object.__setattr__(self, '_previously_accessed_mutables', {})

        self.namespace.config_dir = os.path.abspath(self.namespace.config_dir)
        self.namespace.work_dir = os.path.abspath(self.namespace.work_dir)
        self.namespace.logs_dir = os.path.abspath(self.namespace.logs_dir)

        # Check command line parameters sanity, and error out in case of problem.
        _check_config_sanity(self)

    def set_argument_sources(self, argument_sources: Dict[str, ArgumentSource]) -> None:
        """
        Associate the NamespaceConfig with a dictionary describing where each of
        its arguments came from, e.g. `{ 'email': ArgumentSource.CONFIG_FILE }`.
        This is necessary for making runtime evaluations on whether an argument
        was specified by the user or not (see `set_by_user`).

        For an example of how to build such a dictionary, see
        `certbot._internal.cli.helpful.HelpfulArgumentParser._build_sources_dict`

        :ivar argument_sources: dictionary of argument names to their :class:`ArgumentSource`
        :type argument_sources: :class:`Dict[str, ArgumentSource]`
        """

        # Avoid recursion loop because of the delegation defined in __setattr__
        object.__setattr__(self, '_argument_sources', argument_sources)


    def set_by_user(self, var: str) -> bool:
        """
        Return True if a particular config variable has been set by the user
        (via CLI or config file) including if the user explicitly set it to the
        default, or if it was dynamically set at runtime.  Returns False if the
        variable was assigned a default value.

        Raises an exception if `argument_sources` is not set.
        """
        from certbot._internal.cli.cli_constants import DEPRECATED_OPTIONS
        from certbot._internal.cli.cli_constants import VAR_MODIFIERS
        from certbot._internal.plugins import selection

        if self.argument_sources is None:
            raise RuntimeError(
                "NamespaceConfig.set_by_user called without an ArgumentSources dict. "
                "See NamespaceConfig.set_argument_sources().")

        # We should probably never actually hit this code. But if we do,
        # a deprecated option has logically never been set by the CLI.
        if var in DEPRECATED_OPTIONS:
            return False

        if var in ['authenticator', 'installer']:
            auth, inst = selection.cli_plugin_requests(self)
            if var == 'authenticator':
                return auth is not None
            if var == 'installer':
                return inst is not None

        if var in self.argument_sources and self.argument_sources[var] != ArgumentSource.DEFAULT:
            logger.debug("Var %s=%s (set by user).", var, getattr(self, var))
            return True

        for modifier in VAR_MODIFIERS.get(var, []):
            if self.set_by_user(modifier):
                logger.debug("Var %s=%s (set by user).",
                    var, VAR_MODIFIERS.get(var, []))
                return True

        return False

    def to_dict(self) -> Dict[str, Any]:
        """
        Returns a dictionary mapping all argument names to their values
        """
        return vars(self.namespace)

    def _mark_runtime_override(self, name: str) -> None:
        """
        If an argument_sources dict was set, overwrites an argument's source to
        be ArgumentSource.RUNTIME. Used when certbot sets an argument's values
        at runtime. This also clears the modified value from
        _previously_accessed_mutables since it is no longer needed.
        """
        if self._argument_sources is not None:
            self._argument_sources[name] = ArgumentSource.RUNTIME
            if name in self._previously_accessed_mutables:
                del self._previously_accessed_mutables[name]

    @property
    def argument_sources(self) -> Optional[Dict[str, ArgumentSource]]:
        """Returns _argument_sources after handling any changes to accessed mutable values."""
        # We keep values in _previously_accessed_mutables until we've detected a modification to try
        # to provide up-to-date information when argument_sources is accessed. Once a mutable object
        # has been accessed, it can be modified at any time if a reference to it was kept somewhere
        # else.

        # We copy _previously_accessed_mutables because _mark_runtime_override modifies it.
        for name, prev_value in self._previously_accessed_mutables.copy().items():
            current_value = getattr(self.namespace, name)
            if current_value != prev_value:
                self._mark_runtime_override(name)
        return self._argument_sources

    # Delegate any attribute not explicitly defined to the underlying namespace object.
    #
    # If any mutable namespace attributes are explicitly defined in the future, you'll probably want
    # to take an approach like the one used in __getattr__ and the argument_sources property.

    def __getattr__(self, name: str) -> Any:
        arg_sources = self.argument_sources
        value = getattr(self.namespace, name)
        if arg_sources is not None:
            # If the requested attribute was already modified at runtime, we don't need to track any
            # future changes.
            if name not in arg_sources or arg_sources[name] != ArgumentSource.RUNTIME:
                # If name is already in _previously_accessed_mutables, we don't need to make a copy
                # of it again. If its value was changed, this would have been caught while preparing
                # the return value of the property self.argument_sources accessed earlier in this
                # function.
                if name not in self._previously_accessed_mutables and not _is_immutable(value):
                    self._previously_accessed_mutables[name] = copy.deepcopy(value)
        return value

    def __setattr__(self, name: str, value: Any) -> None:
        self._mark_runtime_override(name)
        setattr(self.namespace, name, value)

    @property
    def server(self) -> str:
        """ACME Directory Resource URI."""
        return self.namespace.server

    @server.setter
    def server(self, server_: str) -> None:
        self._mark_runtime_override('server')
        self.namespace.server = server_

    @property
    def email(self) -> Optional[str]:
        """Email used for registration and recovery contact.

        Use comma to register multiple emails,
        ex: u1@example.com,u2@example.com. (default: Ask).
        """
        return self.namespace.email

    @email.setter
    def email(self, mail: str) -> None:
        self._mark_runtime_override('email')
        self.namespace.email = mail

    @property
    def rsa_key_size(self) -> int:
        """Size of the RSA key."""
        return self.namespace.rsa_key_size

    @rsa_key_size.setter
    def rsa_key_size(self, ksize: int) -> None:
        """Set the rsa_key_size property"""
        self._mark_runtime_override('rsa_key_size')
        self.namespace.rsa_key_size = ksize

    @property
    def elliptic_curve(self) -> str:
        """The SECG elliptic curve name to use.

        Please see RFC 8446 for supported values.
        """
        return self.namespace.elliptic_curve

    @elliptic_curve.setter
    def elliptic_curve(self, ecurve: str) -> None:
        """Set the elliptic_curve property"""
        self._mark_runtime_override('elliptic_curve')
        self.namespace.elliptic_curve = ecurve

    @property
    def key_type(self) -> str:
        """Type of generated private key.

        Only *ONE* per invocation can be provided at this time.
        """
        return self.namespace.key_type

    @key_type.setter
    def key_type(self, ktype: str) -> None:
        """Set the key_type property"""
        self._mark_runtime_override('key_type')
        self.namespace.key_type = ktype

    @property
    def must_staple(self) -> bool:
        """Adds the OCSP Must-Staple extension to the certificate.

        Autoconfigures OCSP Stapling for supported setups
        (Apache version >= 2.3.3 ).
        """
        return self.namespace.must_staple

    @property
    def config_dir(self) -> str:
        """Configuration directory."""
        return self.namespace.config_dir

    @property
    def work_dir(self) -> str:
        """Working directory."""
        return self.namespace.work_dir

    @property
    def accounts_dir(self) -> str:
        """Directory where all account information is stored."""
        return self.accounts_dir_for_server_path(self.server_path)

    @property
    def backup_dir(self) -> str:
        """Configuration backups directory."""
        return os.path.join(self.namespace.work_dir, constants.BACKUP_DIR)

    @property
    def csr_dir(self) -> str:
        """Directory where new Certificate Signing Requests (CSRs) are saved."""
        warnings.warn("NamespaceConfig.csr_dir is deprecated and will be removed in an upcoming "
                      "release of Certbot", DeprecationWarning)
        return os.path.join(self.namespace.config_dir, constants.CSR_DIR)

    @property
    def in_progress_dir(self) -> str:
        """Directory used before a permanent checkpoint is finalized."""
        return os.path.join(self.namespace.work_dir, constants.IN_PROGRESS_DIR)

    @property
    def key_dir(self) -> str:
        """Keys storage."""
        warnings.warn("NamespaceConfig.key_dir is deprecated and will be removed in an upcoming "
                      "release of Certbot", DeprecationWarning)
        return os.path.join(self.namespace.config_dir, constants.KEY_DIR)

    @property
    def temp_checkpoint_dir(self) -> str:
        """Temporary checkpoint directory."""
        return os.path.join(
            self.namespace.work_dir, constants.TEMP_CHECKPOINT_DIR)

    @property
    def no_verify_ssl(self) -> bool:
        """Disable verification of the ACME server's certificate.

        The root certificates trusted by Certbot can be overriden by setting the
        REQUESTS_CA_BUNDLE environment variable.
        """
        return self.namespace.no_verify_ssl

    @property
    def http01_port(self) -> int:
        """Port used in the http-01 challenge.

        This only affects the port Certbot listens on.
        A conforming ACME server will still attempt to connect on port 80.
        """
        return self.namespace.http01_port

    @property
    def http01_address(self) -> str:
        """The address the server listens to during http-01 challenge."""
        return self.namespace.http01_address

    @property
    def https_port(self) -> int:
        """Port used to serve HTTPS.

        This affects which port Nginx will listen on after a LE certificate
        is installed.
        """
        return self.namespace.https_port

    @property
    def pref_challs(self) -> List[str]:
        """List of user specified preferred challenges.

        Sorted with the most preferred challenge listed first.
        """
        return self.namespace.pref_challs

    @property
    def allow_subset_of_names(self) -> bool:
        """Allow only a subset of names to be authorized to perform validations.

        When performing domain validation, do not consider it a failure
        if authorizations can not be obtained for a strict subset of
        the requested domains. This may be useful for allowing renewals for
        multiple domains to succeed even if some domains no longer point
        at this system.
        """
        return self.namespace.allow_subset_of_names

    @property
    def strict_permissions(self) -> bool:
        """Enable strict permissions checks.

        Require that all configuration files are owned by the current
        user; only needed if your config is somewhere unsafe like /tmp/.
        """
        return self.namespace.strict_permissions

    @property
    def disable_renew_updates(self) -> bool:
        """Disable renewal updates.

        If updates provided by installer enhancements when Certbot is being run
        with \"renew\" verb should be disabled.
        """
        return self.namespace.disable_renew_updates

    @property
    def preferred_chain(self) -> Optional[str]:
        """Set the preferred certificate chain.

        If the CA offers multiple certificate chains, prefer the chain whose
        topmost certificate was issued from this Subject Common Name.
        If no match, the default offered chain will be used.
        """
        return self.namespace.preferred_chain

    @property
    def server_path(self) -> str:
        """File path based on ``server``."""
        parsed = parse.urlparse(self.namespace.server)
        return (parsed.netloc + parsed.path).replace('/', os.path.sep)

    def accounts_dir_for_server_path(self, server_path: str) -> str:
        """Path to accounts directory based on server_path"""
        server_path = misc.underscores_for_unsupported_characters_in_path(server_path)
        return os.path.join(
            self.namespace.config_dir, constants.ACCOUNTS_DIR, server_path)

    @property
    def default_archive_dir(self) -> str:  # pylint: disable=missing-function-docstring
        return os.path.join(self.namespace.config_dir, constants.ARCHIVE_DIR)

    @property
    def live_dir(self) -> str:  # pylint: disable=missing-function-docstring
        return os.path.join(self.namespace.config_dir, constants.LIVE_DIR)

    @property
    def renewal_configs_dir(self) -> str:  # pylint: disable=missing-function-docstring
        return os.path.join(
            self.namespace.config_dir, constants.RENEWAL_CONFIGS_DIR)

    @property
    def renewal_hooks_dir(self) -> str:
        """Path to directory with hooks to run with the renew subcommand."""
        return os.path.join(self.namespace.config_dir,
                            constants.RENEWAL_HOOKS_DIR)

    @property
    def renewal_pre_hooks_dir(self) -> str:
        """Path to the pre-hook directory for the renew subcommand."""
        return os.path.join(self.renewal_hooks_dir,
                            constants.RENEWAL_PRE_HOOKS_DIR)

    @property
    def renewal_deploy_hooks_dir(self) -> str:
        """Path to the deploy-hook directory for the renew subcommand."""
        return os.path.join(self.renewal_hooks_dir,
                            constants.RENEWAL_DEPLOY_HOOKS_DIR)

    @property
    def renewal_post_hooks_dir(self) -> str:
        """Path to the post-hook directory for the renew subcommand."""
        return os.path.join(self.renewal_hooks_dir,
                            constants.RENEWAL_POST_HOOKS_DIR)

    @property
    def issuance_timeout(self) -> int:
        """This option specifies how long (in seconds) Certbot will wait
        for the server to issue a certificate.
        """
        return self.namespace.issuance_timeout

    @property
    def new_key(self) -> bool:
        """This option specifies whether Certbot should generate a new private
        key when replacing a certificate, even if reuse_key is set.
        """
        return self.namespace.new_key

    # Magic methods

    def __deepcopy__(self, _memo: Any) -> 'NamespaceConfig':
        # Work around https://bugs.python.org/issue1515 for py26 tests :( :(
        new_ns = copy.deepcopy(self.namespace)
        new_config = type(self)(new_ns)
        # Avoid recursion loop because of the delegation defined in __setattr__
        object.__setattr__(new_config, '_argument_sources', copy.deepcopy(self.argument_sources))
        object.__setattr__(new_config, '_previously_accessed_mutables',
                           copy.deepcopy(self._previously_accessed_mutables))
        return new_config


def _check_config_sanity(config: NamespaceConfig) -> None:
    """Validate command line options and display error message if
    requirements are not met.

    :param config: NamespaceConfig instance holding user configuration
    :type args: :class:`certbot.configuration.NamespaceConfig`

    """
    # Port check
    if config.http01_port == config.https_port:
        raise errors.ConfigurationError(
            "Trying to run http-01 and https-port "
            "on the same port ({0})".format(config.https_port))

    # Domain checks
    if config.namespace.domains is not None:
        for domain in config.namespace.domains:
            # This may be redundant, but let's be paranoid
            util.enforce_domain_sanity(domain)


def dest_namespace(name: str) -> str:
    """ArgumentParser dest namespace (prefix of all destinations)."""
    return name.replace("-", "_") + "_"

class Plugin():
    """Generic plugin."""

    def __init__(self, config: NamespaceConfig, name: str) -> None:
        self.config = config
        self.name = name

    def dest(self, var: str) -> str:
        """Find a destination for given variable ``var``."""
        # this should do exactly the same what ArgumentParser(arg),
        # does to "arg" to compute "dest"
        return self.dest_namespace + var.replace("-", "_")

    @property
    def dest_namespace(self) -> str:
        """ArgumentParser dest namespace (prefix of all destinations)."""
        return dest_namespace(self.name)

class DNSAuthenticator(Plugin):
    """Hacking a DNSAuthenticator

    Emulating certbot call environment
    """

    def conf(self, var: str) -> Any:
        """Find a configuration value for variable ``var``."""
        return self.config[self.dest(var)] # getattr(self.config, self.dest(var))


    def __init__(self, config: NamespaceConfig, name: str) -> None:
        super().__init__(config, name)

        self._attempt_cleanup = False


    @abc.abstractmethod
    def _setup_credentials(self) -> None:  # pragma: no cover
        """
        Establish credentials, prompting if necessary.
        """
        raise NotImplementedError()

    @abc.abstractmethod
    def _perform(self, domain: str, validation_name: str,
                 validation: str) -> None:  # pragma: no cover
        """
        Performs a dns-01 challenge by creating a DNS TXT record.

        :param str domain: The domain being validated.
        :param str validation_domain_name: The validation record domain name.
        :param str validation: The validation record content.
        :raises errors.PluginError: If the challenge cannot be performed
        """
        raise NotImplementedError()

    @abc.abstractmethod
    def _cleanup(self, domain: str, validation_name: str,
                 validation: str) -> None:  # pragma: no cover
        """
        Deletes the DNS TXT record which would have been created by `_perform_achall`.

        Fails gracefully if no such record exists.

        :param str domain: The domain being validated.
        :param str validation_domain_name: The validation record domain name.
        :param str validation: The validation record content.
        """
        raise NotImplementedError()

    def _configure_file(self, key: str, label: str,
                        validator: Optional[Callable[[str], None]] = None) -> None:
        """
        Ensure that a configuration value is available for a path.

        If necessary, prompts the user and stores the result.

        :param str key: The configuration key.
        :param str label: The user-friendly label for this piece of information.
        """

        configured_value = self.conf(key)
        if not configured_value:
            new_value = self._prompt_for_file(label, validator)

            setattr(self.config, self.dest(key), os.path.abspath(os.path.expanduser(new_value)))

    def _configure_credentials(
        self, key: str, label: str, required_variables: Optional[Mapping[str, str]] = None,
        validator: Optional[Callable[['CredentialsConfiguration'], None]] = None
    ) -> 'CredentialsConfiguration':
        """
        As `_configure_file`, but for a credential configuration file.

        If necessary, prompts the user and stores the result.

        Always stores absolute paths to avoid issues during renewal.

        :param str key: The configuration key.
        :param str label: The user-friendly label for this piece of information.
        :param dict required_variables: Map of variable which must be present to error to display.
        :param callable validator: A method which will be called to validate the
            `CredentialsConfiguration` resulting from the supplied input after it has been validated
            to contain the `required_variables`. Should throw a `~certbot.errors.PluginError` to
            indicate any issue.
        """

        def __validator(filename: str) -> None:  # pylint: disable=unused-private-member
            applied_configuration = CredentialsConfiguration(filename, self.dest)

            if required_variables:
                applied_configuration.require(required_variables)

            if validator:
                validator(applied_configuration)

        self._configure_file(key, label, __validator)

        credentials_configuration = CredentialsConfiguration(self.conf(key), self.dest)
        if required_variables:
            credentials_configuration.require(required_variables)

        if validator:
            validator(credentials_configuration)

        return credentials_configuration


class Authenticator(DNSAuthenticator):
    """DNS Authenticator using for Square Dynamic Updates

    This Authenticator uses the Square DNS API to fulfill a dns-01 challenge.
    """

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.credentials: Optional[CredentialsConfiguration] = None

    def getExistingAcmeRecord(self, endpoint, validation_name, headers):
        response = requests.get(endpoint, headers=headers)
        jsonResponse = getJsonResponse(response)

        # Access list of PowerDNS entries
        if self.accessors:
            for accessor in self.accessors:
                jsonResponse = jsonResponse[accessor]

        # Look for matching TXT entry (i.e name == '_acme-challenge.DOMAIN_NAME')
        for record in jsonResponse:
            if record['type'] == 'TXT' and record['name'] == validation_name:
                return record
        return None

    def createAcmeRecord(self, endpoint, headers, validation_name, proofToken):
        response = requests.post(
            endpoint,
            data=json.dumps([{
                'name':validation_name,
                'type':'TXT',
                'content':'"' + proofToken + '"',
                'ttl':'60'
            }]),
            headers=headers
        )
        return getJsonResponse(response)

    def deleteRecord(self, endpoint, delMe, headers):
        response = requests.delete(
            endpoint,
            data=json.dumps([{'id': delMe['id']}]),
            headers=headers
        )
        return getJsonResponse(response)

    def _validate_credentials(self, credentials: CredentialsConfiguration) -> None:
        server = credentials.conf('server')
        if not server.startswith('https://') and not server.startswith('http://'):
            raise errors.PluginError("The DNS manipuation API endpoint ({0}) is not an http(s) URL"
                                     .format(server))

        self.readHeaders = {
            'accept': 'application/json',
            'API-TOKEN': credentials.conf('secret'),
            'X-CSRF-TOKEN': ''
        }
        self.writeHeaders = {
            'content-type': 'application/json'
        }

    def _setup_credentials(self) -> None:
        self.credentials = self._configure_credentials(
            'credentials',
            'RFC 2136 credentials INI file',
            {
                'secret': 'DNS manipuation API endpoint',
                'server': 'Authentication token for API endpoint',
                'getAccess': 'JSON path to list of entries in GET response, e.g. foo.bar.data',
            },
            self._validate_credentials
        )
        getAccess = self.credentials.conf('getAccess')
        if getAccess:
            self.accessors = getAccess.split('.')

    def _perform(self, _domain: str, validation_name: str, validation: str) -> None:
        endpoint = self.credentials.conf('server')
        self._cleanup(_domain, validation_name, validation)
        created = self.createAcmeRecord(endpoint, dict(self.readHeaders, **self.writeHeaders), validation_name, validation)
        if created != None:
            print("POSTed " + created['data'][0]['id'])

    def _cleanup(self, _domain: str, validation_name: str, validation: str) -> None:
        endpoint = self.credentials.conf('server')
        delMe = self.getExistingAcmeRecord(endpoint, validation_name, self.readHeaders)
        if delMe != None:
            print("DELETEd " + self.deleteRecord(endpoint, delMe, dict(self.readHeaders, **self.writeHeaders))['data'][0]['id'])

def main(config, proofToken):
    try:
        a = Authenticator(config, 'dns-rfc2136')
        a._setup_credentials()
        a._perform('fdpcloud.org', '_acme-challenge.fdpcloud.org', proofToken)
        a._cleanup('fdpcloud.org', '_acme-challenge.fdpcloud.org', proofToken)

    except HTTPError as http_err:
        print(f'HTTP error occurred: {http_err}')
    except Exception as err:
        print(f'Other error occurred: {err}')
        extype, value, tb = sys.exc_info()
        traceback.print_exc()
        pdb.post_mortem(tb)

def getJsonResponse(response):
    response.raise_for_status()
    jsonResponse = response.json()
    if jsonResponse['success'] is False:
        raise ValueError(
            'Expected success to be true, gpt {success}\n  {url}\n  {headers}\n  {body}'.format(
                success=repr(jsonResponse['success']),
                url = response.request.url,
                headers = response.request.headers,
                bodt = response.request.body
            ))
    return jsonResponse

config = {'config_file': None, 'verbose_count': 0, 'verbose_level': None, 'text_mode': False, 'max_log_backups': 0, 'preconfigured_renewal': True, 'noninteractive_mode': False, 'force_interactive': False, 'domains':['fdpcloud.org', '*.fdpcloud.org'], 'eab_kid': None, 'eab_hmac_key': None, 'certname': None, 'dry_run': False, 'register_unsafely_without_email': False, 'email': 'webmaster@fdpcloud.org', 'eff_email': None, 'reinstall': False, 'expand': False, 'renew_by_default': False, 'renew_with_new_domains': False, 'reuse_key': False, 'allow_subset_of_names': False, 'tos': False, 'account': None, 'duplicate': False, 'quiet': False, 'staging': False, 'debug': False, 'debug_challenges': False, 'no_verify_ssl': False, 'http01_port': 80, 'http01_address': '', 'https_port': 443, 'break_my_certs': False, 'rsa_key_size': 2048, 'key_type': 'rsa', 'elliptic_curve': 'secp256r1', 'must_staple': False, 'redirect': None, 'hsts': None, 'uir': None, 'staple': None, 'strict_permissions': False, 'preferred_chain': None, 'pref_challs': ['dns-01'], 'pre_hook': None, 'post_hook': None, 'renew_hook': None, 'random_sleep_on_renew': True, 'deploy_hook': None, 'validate_hooks': True, 'directory_hooks': True, 'disable_renew_updates': False, 'autorenew': True, 'os_packages_only': None, 'no_self_upgrade': None, 'no_bootstrap': None, 'no_permissions_check': None, 'auto_hsts': False, 'user_agent': None, 'user_agent_comment': None, 'csr': None, 'reason': 0, 'delete_after_revoke': None, 'checkpoints': 1, 'init': False, 'prepare': False, 'ifaces': None, 'cert_path': '/etc/apache2/sites-available/subdomains.d/cert.pem', 'key_path': None, 'fullchain_path': '/etc/apache2/sites-available/subdomains.d/chain.pem', 'chain_path': '/etc/apache2/sites-available/subdomains.d/chain.pem', 'config_dir': '/etc/letsencrypt', 'work_dir': '/var/lib/letsencrypt', 'logs_dir': '/var/log/letsencrypt', 'server': 'https://acme-v02.api.letsencrypt.org/directory', 'configurator': None, 'authenticator': 'dns-rfc2136', 'installer': None, 'apache': False, 'nginx': False, 'standalone': False, 'manual': False, 'webroot': False, 'dns_cloudflare': False, 'dns_cloudxns': False, 'dns_digitalocean': False, 'dns_dnsimple': False, 'dns_dnsmadeeasy': False, 'dns_gehirn': False, 'dns_google': False, 'dns_linode': False, 'dns_luadns': False, 'dns_nsone': False, 'dns_ovh': False, 'dns_rfc2136': False, 'dns_route53': False, 'dns_sakuracloud': False, 'apache_enmod': 'a2enmod', 'apache_dismod': 'a2dismod', 'apache_le_vhost_ext': '-le-ssl.conf', 'apache_server_root': '/etc/apache2', 'apache_vhost_root': None, 'apache_logs_root': '/var/log/apache2', 'apache_challenge_location': '/etc/apache2', 'apache_handle_modules': True, 'apache_handle_sites': True, 'apache_ctl': 'apache2ctl', 'apache_bin': None,
          'manual_auth_hook': None, 'manual_cleanup_hook': None,
          'manual_public_ip_logging_ok': None, 'webroot_path': [], 'webroot_map': {}, 'verb':'certonly',
          'dns_rfc2136_propagation_seconds': 60, 'dns_rfc2136_credentials': './dns-json_record_key-hosting_nl.ini',
          }

main(config, 'YT0jPoU75j504zs7NTVzFJBSV07mFCIrkOJ_y5l8KHm')
