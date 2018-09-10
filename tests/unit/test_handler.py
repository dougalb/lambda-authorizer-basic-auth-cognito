"""
   Copyright 2018 Amazon.com, Inc. and its affiliates. All Rights Reserved.

   Licensed under the MIT License. See the LICENSE accompanying this file
   for the specific language governing permissions and limitations under
   the License.
"""

import json
import pytest
from lambda_authorizer_basic_auth_cognito import app


@pytest.fixture()
def apigw_auth_event():
    """ Generates API GW Authorizer REQUEST Event"""

    return {
    "type": "REQUEST",
    "methodArn": "arn:aws:execute-api:us-east-1:123456789012:s4x3opwd6i/test/GET/request",
    "resource": "/request",
    "path": "/request",
    "httpMethod": "GET",
    "headers": {
        "X-AMZ-Date": "20170718T062915Z",
        "Accept": "*/*",
        "Authorization": "Basic ZG91Z2FsYjpteXBhc3N3b3Jk",
        "CloudFront-Viewer-Country": "US",
        "CloudFront-Forwarded-Proto": "https",
        "CloudFront-Is-Tablet-Viewer": "false",
        "CloudFront-Is-Mobile-Viewer": "false",
        "User-Agent": "...",
        "X-Forwarded-Proto": "https",
        "CloudFront-Is-SmartTV-Viewer": "false",
        "Host": "....execute-api.us-east-1.amazonaws.com",
        "Accept-Encoding": "gzip, deflate",
        "X-Forwarded-Port": "443",
        "X-Amzn-Trace-Id": "...",
        "Via": "...cloudfront.net (CloudFront)",
        "X-Amz-Cf-Id": "...",
        "X-Forwarded-For": "..., ...",
        "Postman-Token": "...",
        "cache-control": "no-cache",
        "CloudFront-Is-Desktop-Viewer": "true",
        "Content-Type": "application/x-www-form-urlencoded"
    },
    "queryStringParameters": {
        "QueryString1": "queryValue1"
    },
    "pathParameters": {},
    "stageVariables": {
        "StageVar1": "stageValue1"
    },
    "requestContext": {
        "path": "/request",
        "accountId": "123456789012",
        "resourceId": "05c7jb",
        "stage": "test",
        "requestId": "...",
        "identity": {
            "apiKey": "...",
            "sourceIp": "..."
        },
        "resourcePath": "/request",
        "httpMethod": "GET",
        "apiId": "s4x3opwd6i"
    }
}


def test_lambda_handler(apigw_auth_event):

    ret = app.lambda_handler(apigw_auth_event, "")
    assert ret == {'policyDocument': {'Version': '2012-10-17', 'Statement': [{'Action': 'execute-api:Invoke', 'Resource': ['arn:aws:execute-api:us-east-1:123456789012:s4x3opwd6i/test/GET/request'], 'Effect': 'Allow'}]}, 'principalId': '123456789012'}
