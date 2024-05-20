import logging
import sys

from opentdf import TDFClient, NanoTDFClient, OIDCCredentials, LogLevel, TDFStorageType

logger = logging.getLogger("xtest")
logging.basicConfig()
logging.getLogger().setLevel(logging.DEBUG)

KAS_URL = "http://localhost:8080/kas"

def main():
    function, source, target = sys.argv[1:4]

    oidc_creds = OIDCCredentials()
    oidc_creds.set_client_credentials_client_secret(
        client_id="opentdf",
        client_secret="secret",
        organization_name="opentdf",
        oidc_endpoint="http://localhost:8888",
    )

    is_nano = source.endswith(".ntdf") or target.endswith(".ntdf")
    client = (
        NanoTDFClient(oidc_credentials=oidc_creds, kas_url=KAS_URL)
        if is_nano
        else TDFClient(oidc_credentials=oidc_creds, kas_url=KAS_URL)
    )
    client.enable_console_logging(LogLevel.Debug)
    client.add_data_attribute(
        "https://example.com/attr/Classification/value/S", KAS_URL
    )
    client.add_data_attribute("https://example.com/attr/COI/value/PRX", KAS_URL)

    if function == "encrypt":
        encrypt_file(client, source, target)
    elif function == "decrypt":
        decrypt_file(client, source, target)
    else:
        logger.error("Python -- invalid function type provided")
        sys.exit(1)


def encrypt_file(client, source, target):
    logger.info(f"Python -- Encrypting file {source} to {target}")
    sampleTxtStorage = TDFStorageType()
    sampleTxtStorage.set_tdf_storage_file_type(source)
    client.encrypt_file(sampleTxtStorage, target)


def decrypt_file(client, source, target):
    logger.info(f"Python -- Decrypting file {source} to {target}")
    sampleTdfStorage = TDFStorageType()
    sampleTdfStorage.set_tdf_storage_file_type(source)
    client.decrypt_file(sampleTdfStorage, target)


if __name__ == "__main__":
    main()
