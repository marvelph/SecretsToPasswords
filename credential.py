import base64
from csv import DictWriter
from xml.etree import ElementTree

source_file_name = "SPEF/Secrets.xml"
destination_file_name = "Credentials.csv"


def to_text(element):
    if element is None:
        return ""
    elif element.text is None:
        return ""
    else:
        return element.text


def concat_text(first, second):
    if second == "":
        return first
    else:
        return first + "\n" + second


with open(destination_file_name, "w", newline="") as file:
    fieldnames = ["Title", "URL", "Username", "Password", "Notes", "OTPAuth"]
    writer = DictWriter(file, fieldnames=fieldnames, lineterminator="\n")
    writer.writeheader()

    tree = ElementTree.parse(source_file_name)
    secrets = tree.getroot()

    credentials = secrets.find("credentials")
    if credentials is not None:
        for credential in credentials:
            trashed_text = to_text(credential.find("trashed"))
            if trashed_text == "0":
                identifier_text = to_text(credential.find("identifier"))
                name_text = to_text(credential.find("name"))
                notes_text = to_text(credential.find("notes"))
                # Normalise newline characters.
                notes_text = notes_text.replace("\u2028", "\n")

                # Ignore the second and subsequent one-time passwords.
                one_time_password_text = ""
                one_time_password = credential.find("oneTimePassword")
                if one_time_password is not None:
                    algorithm_text = to_text(one_time_password.find("algorithm"))
                    digits_text = to_text(one_time_password.find("digits"))
                    period_text = to_text(one_time_password.find("period"))
                    seed_text = base64.b32encode(base64.b64decode(to_text(one_time_password.find("seed")))).decode()
                    one_time_password_text = f"otpauth://totp?secret={seed_text}&algorithm={algorithm_text}&period={period_text}&digits={digits_text}"

                secret_text = ""
                secrets = credential.find("secrets")
                if secrets is not None:
                    for secret in secrets:
                        archived_text = to_text(secret.find("archived"))
                        if archived_text == "0":
                            if secret_text == "":
                                secret_text = to_text(secret.find("secretValue"))

                            # Add the second and subsequent passwords to the memo.
                            else:
                                additional_secret_text = to_text(secret.find("secretValue"))
                                if additional_secret_text != "":
                                    kind_text = to_text(secret.find("kind"))
                                    if kind_text == "1":
                                        notes_text = concat_text(f"PIN : {additional_secret_text}", notes_text)
                                    else:
                                        notes_text = concat_text(f"パスワード : {additional_secret_text}", notes_text)

                # Services add to the notes.
                services = credential.find("services")
                if services is not None:
                    for service in services:
                        address_text = to_text(service.find("address"))
                        notes_text = concat_text(f"URL : {address_text}", notes_text)

                writer.writerow(
                    {
                        "Title": name_text,
                        "URL": "",
                        "Username": identifier_text,
                        "Password": secret_text,
                        "Notes": notes_text,
                        "OTPAuth": one_time_password_text,
                    }
                )
