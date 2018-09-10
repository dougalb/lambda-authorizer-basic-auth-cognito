"""
   Copyright 2018 Amazon.com, Inc. and its affiliates. All Rights Reserved.

   Licensed under the MIT License. See the LICENSE accompanying this file
   for the specific language governing permissions and limitations under
   the License.
"""
from __future__ import print_function

import os
import re
import json
import logging
import base64

import boto3
from aws_xray_sdk.core import xray_recorder
from aws_xray_sdk.core import patch_all

patch_all()

# Static code used for DynamoDB connection and logging
client = boto3.client('cognito-idp')
user_pool_id = os.environ['USER_POOL_ID']
client_id = os.environ['CLIENT_ID']
log_level = os.environ['LOG_LEVEL']
log = logging.getLogger(__name__)
logging.getLogger().setLevel(log_level)


def lambda_handler(event, context):
    log.debug("Event: " + json.dumps(event))

    # Ensure the incoming Lambda event is for a request authorizer
    if event['type'] != 'REQUEST':
        raise Exception('Unauthorized')

    try:
        # Set the principalId to the accountId making the authorizer call
        principalId = event['requestContext']['accountId']

        tmp = event['methodArn'].split(':')
        apiGatewayArnTmp = tmp[5].split('/')
        awsAccountId = tmp[4]

        policy = AuthPolicy(principalId, awsAccountId)
        policy.restApiId = apiGatewayArnTmp[0]
        policy.region = tmp[3]
        policy.stage = apiGatewayArnTmp[1]

        # Get authorization header in lowercase
        authorization_header = {k.lower(): v for k, v in event['headers'].items() if k.lower() == 'authorization'}
        log.debug("authorization: " + json.dumps(authorization_header))

        # Get the username:password hash from the authorization header
        username_password_hash = authorization_header['authorization'].split()[1]
        log.debug("username_password_hash: " + username_password_hash)

        # Decode username_password_hash and get username/password
        username = base64.standard_b64decode(username_password_hash).split(':')[0]
        password = base64.standard_b64decode(username_password_hash).split(':')[1]
        log.info("username: " + username)

        # Call Cognito
        cognito_auth_response = client.admin_initiate_auth(
            UserPoolId=user_pool_id,
            ClientId=client_id,
            AuthFlow='ADMIN_NO_SRP_AUTH',
            AuthParameters={
                'USERNAME': username,
                'PASSWORD': password
            }
        )

        # Validate the response from Cognito
        if cognito_auth_response['ResponseMetadata']['HTTPStatusCode'] == 200:
            log.info("Successful authentication against Cognito User Pool!")
            policy.allowMethod(event['requestContext']['httpMethod'], event['path'])
        else:
            log.info("Failed to authenticate against Cognito User Pool")
            policy.denyMethod(event['requestContext']['httpMethod'], event['path'])

        # Build the policy
        authResponse = policy.build()
        log.debug("authResponse: " + json.dumps(authResponse))

        return authResponse
    except Exception:
        raise Exception('Unauthorized')


class HttpVerb:
    GET = "GET"
    POST = "POST"
    PUT = "PUT"
    PATCH = "PATCH"
    HEAD = "HEAD"
    DELETE = "DELETE"
    OPTIONS = "OPTIONS"
    ALL = "*"


class AuthPolicy(object):
    awsAccountId = ""
    """The AWS account id the policy will be generated for. This is used to create the method ARNs."""
    principalId = ""
    """The principal used for the policy, this should be a unique identifier for the end user."""
    version = "2012-10-17"
    """The policy version used for the evaluation. This should always be '2012-10-17'"""
    pathRegex = "^[/.a-zA-Z0-9-\*]+$"
    """The regular expression used to validate resource paths for the policy"""

    """these are the internal lists of allowed and denied methods. These are lists
    of objects and each object has 2 properties: A resource ARN and a nullable
    conditions statement.
    the build method processes these lists and generates the approriate
    statements for the final policy"""
    allowMethods = []
    denyMethods = []

    restApiId = "*"
    """The API Gateway API id. By default this is set to '*'"""
    region = "*"
    """The region where the API is deployed. By default this is set to '*'"""
    stage = "*"
    """The name of the stage used in the policy. By default this is set to '*'"""

    def __init__(self, principal, awsAccountId):
        self.awsAccountId = awsAccountId
        self.principalId = principal
        self.allowMethods = []
        self.denyMethods = []

    def _addMethod(self, effect, verb, resource, conditions):
        """Adds a method to the internal lists of allowed or denied methods. Each object in
        the internal list contains a resource ARN and a condition statement. The condition
        statement can be null."""
        if verb != "*" and not hasattr(HttpVerb, verb):
            raise NameError("Invalid HTTP verb " + verb + ". Allowed verbs in HttpVerb class")
        resourcePattern = re.compile(self.pathRegex)
        if not resourcePattern.match(resource):
            raise NameError("Invalid resource path: " + resource + ". Path should match " + self.pathRegex)

        if resource[:1] == "/":
            resource = resource[1:]

        resourceArn = ("arn:aws:execute-api:" +
            self.region + ":" +
            self.awsAccountId + ":" +
            self.restApiId + "/" +
            self.stage + "/" +
            verb + "/" +
            resource)

        if effect.lower() == "allow":
            self.allowMethods.append({
                'resourceArn': resourceArn,
                'conditions': conditions
            })
        elif effect.lower() == "deny":
            self.denyMethods.append({
                'resourceArn': resourceArn,
                'conditions': conditions
            })

    def _getEmptyStatement(self, effect):
        """Returns an empty statement object prepopulated with the correct action and the
        desired effect."""
        statement = {
            'Action': 'execute-api:Invoke',
            'Effect': effect[:1].upper() + effect[1:].lower(),
            'Resource': []
        }

        return statement

    def _getStatementForEffect(self, effect, methods):
        """This function loops over an array of objects containing a resourceArn and
        conditions statement and generates the array of statements for the policy."""
        statements = []

        if len(methods) > 0:
            statement = self._getEmptyStatement(effect)

            for curMethod in methods:
                if curMethod['conditions'] is None or len(curMethod['conditions']) == 0:
                    statement['Resource'].append(curMethod['resourceArn'])
                else:
                    conditionalStatement = self._getEmptyStatement(effect)
                    conditionalStatement['Resource'].append(curMethod['resourceArn'])
                    conditionalStatement['Condition'] = curMethod['conditions']
                    statements.append(conditionalStatement)

            statements.append(statement)

        return statements

    def allowAllMethods(self):
        """Adds a '*' allow to the policy to authorize access to all methods of an API"""
        self._addMethod("Allow", HttpVerb.ALL, "*", [])

    def denyAllMethods(self):
        """Adds a '*' allow to the policy to deny access to all methods of an API"""
        self._addMethod("Deny", HttpVerb.ALL, "*", [])

    def allowMethod(self, verb, resource):
        """Adds an API Gateway method (Http verb + Resource path) to the list of allowed
        methods for the policy"""
        self._addMethod("Allow", verb, resource, [])

    def denyMethod(self, verb, resource):
        """Adds an API Gateway method (Http verb + Resource path) to the list of denied
        methods for the policy"""
        self._addMethod("Deny", verb, resource, [])

    def allowMethodWithConditions(self, verb, resource, conditions):
        """Adds an API Gateway method (Http verb + Resource path) to the list of allowed
        methods and includes a condition for the policy statement. More on AWS policy
        conditions here: http://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements.html#Condition"""
        self._addMethod("Allow", verb, resource, conditions)

    def denyMethodWithConditions(self, verb, resource, conditions):
        """Adds an API Gateway method (Http verb + Resource path) to the list of denied
        methods and includes a condition for the policy statement. More on AWS policy
        conditions here: http://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements.html#Condition"""
        self._addMethod("Deny", verb, resource, conditions)

    def build(self):
        """Generates the policy document based on the internal lists of allowed and denied
        conditions. This will generate a policy with two main statements for the effect:
        one statement for Allow and one statement for Deny.
        Methods that includes conditions will have their own statement in the policy."""
        if ((self.allowMethods is None or len(self.allowMethods) == 0) and
            (self.denyMethods is None or len(self.denyMethods) == 0)):
            raise NameError("No statements defined for the policy")

        policy = {
            'principalId': self.principalId,
            'policyDocument': {
                'Version': self.version,
                'Statement': []
            }
        }

        policy['policyDocument']['Statement'].extend(self._getStatementForEffect("Allow", self.allowMethods))
        policy['policyDocument']['Statement'].extend(self._getStatementForEffect("Deny", self.denyMethods))

        return policy
