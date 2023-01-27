const https = require('https');

exports.handler = async function(event, context, callback) {        
    console.log('Received event:', JSON.stringify(event, null, 2));

    // A simple request-based authorizer example to demonstrate how to use request 
    // parameters to allow or deny a request. In this example, a request is  
    // authorized if the client-supplied headerauth1 header, QueryString1
    // query parameter, and stage variable of StageVar1 all match
    // specified values of 'headerValue1', 'queryValue1', and 'stageValue1',
    // respectively.

    // Retrieve request parameters from the Lambda function input:
    var headers = event.headers;
        
    // Parse the input for the parameter values
    var tmp2 = event.methodArn.split(':');
    var apiGatewayArnTmp = tmp2[5].split('/');
    var resourcev2 = tmp2[0] + ":" + tmp2[1] + ":" + tmp2[2] + ":" + tmp2[3] + ":" + tmp2[4] + ":" + apiGatewayArnTmp[0] + '/*/*'; 
        
    // Perform authorization to return the Allow policy for correct parameters and 
    // the 'Unauthorized' error, otherwise.
    var condition = {};
    condition.IpAddress = {};

    var bearerToken = headers.Authorization == undefined ? headers.authorization : headers.Authorization;
    if (bearerToken.startsWith('Bearer') && bearerToken === 'Bearer my-api-key') {
        try {
            console.log('Bearer OK');
            callback(null, generateAllow('me', resourcev2));
        } catch (error) {
            console.log('error is:', error);
            callback("Unauthorized");
        }
    }  else {
        callback("Unauthorized");
    }
}
     
// Help function to generate an IAM policy
var generatePolicy = function(principalId, effect, resource) {
    // Required output:
    var authResponse = {};
    authResponse.principalId = principalId;
    if (effect && resource) {
        var policyDocument = {};
        policyDocument.Version = '2012-10-17'; // default version
        policyDocument.Statement = [];
        var statementOne = {};
        statementOne.Action = 'execute-api:Invoke'; // default action
        statementOne.Effect = effect;
        statementOne.Resource = resource;
        policyDocument.Statement[0] = statementOne;
        authResponse.policyDocument = policyDocument;
    }
    // Optional output with custom properties of the String, Number or Boolean type.
    authResponse.context = {
        "stringKey": "stringval",
        "numberKey": 123,
        "booleanKey": true
    };
    return authResponse;
}
     
var generateAllow = function(principalId, resource) {
    return generatePolicy(principalId, 'Allow', resource);
}
     
var generateDeny = function(principalId, resource) {
    return generatePolicy(principalId, 'Deny', resource);
}
