import AWS from "aws-sdk";

AWS.config.update({
    region: "eu-west-2"
});

const cognito = new AWS.CognitoIdentityServiceProvider();

export default cognito;