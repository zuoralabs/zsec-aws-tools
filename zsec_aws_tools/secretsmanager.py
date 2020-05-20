from typing import Dict, Any
from toolz import keyfilter

import attr


@attr.s(auto_attribs=True)
class Secret:
    name: str
    config: Dict[str, Any]
    service_client: Any

    def create(self):
        response = self.service_client.create_secret(
            Name=self.name,
            **keyfilter(
                lambda x: x in ['Description', 'KMSKeyId', 'SecretsBinary', 'SecretString', 'Tags', 'ClientRequestToken'],
                self.config,
            )
        )

    def exists(self):
        try:
            response = self.service_client.describe_secret(SecretId=self.name)
            return True
        except self.service_client.exceptions.ResourceNotFoundException:
            return False

    def describe(self):
        return self.service_client.describe_secret(SecretId=self.name)

    def put(self):
        if self.exists():
            # put_secret_value only works if secret exists
            self.service_client.put_secret_value(SecretId=self.name, SecretString=self.config['SecretString'])
        else:
            self.create()
