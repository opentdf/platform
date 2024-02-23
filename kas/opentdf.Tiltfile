# Tiltfile with helpers for configuring OpenTDF
# reference https://docs.tilt.dev/api.html
# extensions https://github.com/tilt-dev/tilt-extensions
# helm remote usage https://github.com/tilt-dev/tilt-extensions/tree/master/helm_remote#additional-parameters

load("ext://helm_remote", "helm_remote")
load("ext://helm_resource", "helm_resource", "helm_repo")
load("ext://min_tilt_version", "min_tilt_version")
load("ext://restart_process", "docker_build_with_restart")

min_tilt_version("0.31")

# Versions of things backend to pull (attributes, kas, etc)
BACKEND_CHART_TAG = os.environ.get("BACKEND_LATEST_VERSION", "0.0.0-sha-02d27b5")
FRONTEND_CHART_TAG = os.environ.get("FRONTEND_LATEST_VERSION", "1.4.1")

CONTAINER_REGISTRY = os.environ.get("CONTAINER_REGISTRY", "ghcr.io")
POSTGRES_PASSWORD = "myPostgresPassword"
OIDC_CLIENT_SECRET = "myclientsecret"
opaPolicyPullSecret = os.environ.get("CR_PAT")

TESTS_DIR = os.getcwd()


def from_dotenv(path, key):
    # Read a variable from a `.env` file
    return str(local('. "{}" && echo "${}"'.format(path, key))).strip()


all_secrets = read_yaml("./mocks/mock-secrets.yaml")


def prefix_list(prefix, list):
    return [x for y in zip([prefix] * len(list), list) for x in y]


def dict_to_equals_list(dict):
    return ["%s=%s" % (k, v) for k, v in dict.items()]


def dict_to_helm_set_list(dict):
    combined = dict_to_equals_list(dict)
    return prefix_list("--set", combined)


docker_build(
    "gokas",
    context=".",
    only=[
        './go.mod',
        './go.sum',
        './makefile',
        './cmd',
        './internal',
        './pkg',
        './plugins',
        './scripts',
        './softhsm2-debug.conf',
    ],
    target="server-debug",
)


def ingress(external_port="65432"):
    helm_repo(
        "k8s-in",
        "https://kubernetes.github.io/ingress-nginx",
        labels="utility",
    )
    helm_resource(
        "ingress-nginx",
        "k8s-in/ingress-nginx",
        flags=[
            "--version",
            "4.0.16",
        ]
        + dict_to_helm_set_list(
            {
                "controller.config.large-client-header-buffers": "20 32k",
                "controller.admissionWebhooks.enabled": "false",
            }
        ),
        labels="third-party",
        port_forwards="{}:80".format(external_port),
        resource_deps=["k8s-in"],
    )


# values: list of values files
# set: dictionary of value_name: value pairs
# extra_helm_parameters: only valid when devmode=False; passed to underlying `helm update` command
def backend(values=[], set={}, resource_deps=[]):
    set_values = {
        "entity-resolution.secret.keycloak.clientSecret": "123-456",
        "secrets.opaPolicyPullSecret": opaPolicyPullSecret,
        "secrets.oidcClientSecret": OIDC_CLIENT_SECRET,
        "secrets.postgres.dbPassword": POSTGRES_PASSWORD,
        "kas.auth.http://localhost:65432/auth/realms/tdf.discoveryBaseUrl": "http://keycloak-http/auth/realms/tdf",
        "kas.envConfig.ecCert": all_secrets["KAS_EC_SECP256R1_CERTIFICATE"],
        "kas.envConfig.cert": all_secrets["KAS_CERTIFICATE"],
        "kas.envConfig.ecPrivKey": all_secrets["KAS_EC_SECP256R1_PRIVATE_KEY"],
        "kas.envConfig.privKey": all_secrets["KAS_PRIVATE_KEY"],
        "kas.livenessProbeOverride.grpc.port": "5000",
        "kas.readinessProbeOverride.grpc.port": "5000",
        "kas.image.repo": "gokas",
        "kas.extraConfigMapData.KAS_URL": "http://localhost:65432/api/kas",
    }
    set_values.update(set)

    helm_remote(
        "backend",
        repo_name="oci://ghcr.io/opentdf/charts",
        values=values,
        version=BACKEND_CHART_TAG,
        set=dict_to_equals_list(set_values),
    )
    for x in ["attributes", "entitlement-store"]:
        k8s_resource(x, labels="opentdf", resource_deps=["postgresql"])
    k8s_resource(
        "kas",
        labels="opentdf",
        resource_deps=["attributes", "keycloak"],
        port_forwards="9000:5000"
    )


def frontend(values=[], set={}, resource_deps=[]):
    helm_remote(
        "abacus",
        repo_name="oci://ghcr.io/opentdf/charts",
        values=values,
        version=FRONTEND_CHART_TAG,
        set=dict_to_equals_list(set),
    )
    # resource("abacus", labels="opentdf", resource_deps=resource_deps)


def opentdf_cluster_with_ingress(external_port=65432, start_frontend=True):
    ingress(external_port=external_port)

    backend(
        set={
            ("%s.ingress.enabled" % s): "true"
            for s in [
                "attributes",
                "entitlements",
                "kas",
                "keycloak",
                "entitlement-store",
            ]
        },
        values=[TESTS_DIR + "/mocks/values.yaml"],
        resource_deps=["ingress-nginx"],
    )

    if start_frontend:
        frontend(
            set={
                "basePath": "",
                "fullnameOverride": "abacus",
                "oidc.clientId": "dcr-test",
                "oidc.queryRealms": "tdf",
                "oidc.serverUrl": "http://localhost:65432/auth/",
            },
            values=[TESTS_DIR + "/mocks/frontend-ingress-values.yaml"],
            resource_deps=["backend"],
        )
