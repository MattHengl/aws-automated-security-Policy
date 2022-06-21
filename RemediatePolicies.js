/*!
     * Copyright 2017-2017 Mutual of Enumclaw. All Rights Reserved.
     * License: Public
*/ 

//Mutual of Enumclaw 
//
//Matthew Hengl and Jocelyn Borovich - 2019 :) :)
//
//Main file that controls remediation and notifications of all IAM Policy events. 
//Remediates actions when possible or necessary based on launch type and tagging. Then, notifies the user/security. 

//Make sure to that the master.invalid call does NOT have a ! infront of it
//Make sure to delete or comment out the change in the process.env.environtment

// import  { IAM }  from 'aws-sdk';
// import { Master, path } from 'aws-automated-master-class';
// import * as epsagon from 'epsagon';


const AWS = require('aws-sdk');
AWS.config.update({region: process.env.region});
let iam = new AWS.IAM();
const epsagon = require('epsagon');
const Master = require("aws-automated-master-class/MasterClass").handler;
let path = require("aws-automated-master-class/MasterClass").path; 
let master = new Master();
let callRemediate = remediate;


//Only used for testing purposes
setIamFunction = (value, funct) => {
    iam[value] = funct;
 };

async function handler(event) { 

    try{
        console.log(process.env.accNum1);
        console.log(process.env.accNum2);

        let resourceName = 'policyArn';
        console.log(JSON.stringify(event));
        path.p = 'Path: \nEntering handleEvent';

        event = master.devTest(event);
        //Checks the event log for any previous errors. Stops the function if there is an error. 
        if (master.errorInLog(event)) {
            console.log(path.p);
            return; 
        }

        //Checks if the log came from this function, quits the program if it does.
        if (master.selfInvoked(event)) {
            console.log(path.p);
            return;
        }
        if (event.detail.eventName == "CreatePolicy") {
            console.log(`${event.detail.requestParameters.policyName} is being inspected----------`); 
        } else {
            console.log(`${event.detail.requestParameters.policyArn} is being inspected----------`); 
        }
        
        console.log(`Event name is ${event.detail.eventName}---------- `);

        //Checks to see who is doing the action, if it's one of the two interns. RUN IT!
        if(event.detail.eventName == "CreatePolicy"){
            resourceName = "policyName";
        }
        //if(master.checkKeyUser(event, resourceName)){
            //checks if the log is invalid
            //Remove the ! when not testing
            if (master.invalid(event)) {
                    await master.notifyUser(event, await callRemediate(event), 'Policy');    
            }
        //}
        console.log(path.p); 
    }catch(e) {
        console.log(e);
        path.p += '\nERROR';
        console.log(path.p);
        return e;
    } 
}
async function remediate(event) {

    path.p += '\nEntered the remediation function';
   
   //Sets up required parameters for remediation
    const erp = event.detail.requestParameters;
    const ere = event.detail.responseElements;
    
    let params = {PolicyArn: erp.policyArn};
    let results = master.getResults(event, {});

    //Decides, based on the incoming event, which function to call to perform remediation
    try {
        switch(results.Action){
            case "CreatePolicy":
                path.p+='\nCreatePolicy';
                params.PolicyArn = ere.policy.arn;
                await overrideFunction('deletePolicy', params);
                results.ResourceName = ere.policy.arn;
                results.Response = "DeletePolicy";
            break;
            case "DeletePolicy":
                path.p+='\nDeletePolicy';
                params.PolicyName = erp.policyName;
                let arnIndex = erp.policyArn.indexOf("/" ) + 1;
                results.ResourceName = erp.policyArn.substring(arnIndex);
                results.Response = "Remediation could not be performed";
            break;
            case "CreatePolicyVersion":
                path.p+='\nCreatePolicyVersion';
                let versionArray = await iam.listPolicyVersions(params).promise();
                console.log(versionArray);
                let oldVersionNum = versionArray.Versions[0].VersionId;
                let newVersionNum = versionArray.Versions[1].VersionId;
                params.VersionId = newVersionNum;
                await overrideFunction('setDefaultPolicyVersion', params);
                params.VersionId = oldVersionNum;
                await overrideFunction('deletePolicyVersion', params);
                results.ResourceName = erp.policyArn;
                results.VersionId = oldVersionNum;
                results.Response = "DeletePolicyVersion";
            break;
            case "SetDefaultPolicyVersion":
                path.p += '\nSetDefaultPolicyVersion';
                //setting the default back to 0 in the list array
                let versionArray2 = await iam.listPolicyVersions(params).promise();
                console.log(versionArray2);
                console.log('After List');
                params.VersionId = versionArray2.Versions[0].VersionId;
                await overrideFunction('setDefaultPolicyVersion', params);
                console.log('After Set');
                results.ResourceName = erp.policyArn;
                results["Old Default Version"] = erp.versionId;
                results["Reset Default Version"] = versionArray2.Versions[0].VersionId;
                results.Response = "SetDefaultPolicyVersion";
            break;
            case "DeletePolicyVersion":
                path.p+='\nDeletePolicyVersion';
                results["Deleted Version"] = erp.versionId;
                results.Response = "Remediation could not be performed";
            break;
            default:
                path.p+='\nUnexpected Action found';
        }
    } catch(e) {
        console.log(e); 
        path.p += '\nERROR';
        return e;
    }

    results.Reason = 'Improper Launch';

    if(results.Response == 'Remediation could not be performed'){
        delete results.Reason;
    }
    path.p += '\nRemediation was finished, notifying user now';
    console.log(results);
    return results;
}

async function overrideFunction(apiFunction, params){
    if(process.env.run == 'false'){
        // epsagon.label('remediate','true');
        await setIamFunction(apiFunction, (params) => {
            console.log(`Overriding ${apiFunction}`);
            return {promise: () => {}};
        });
    }
    await iam[apiFunction](params).promise();
};

// //overrides the given function (only for jest testing)
// export function setIamFunction (value, funct){
//     iam[value] = funct;
// };

// export function setRemediate(funct){
//     callRemediate = funct;
// };
 
// export function setFunction(value, funct){
//     iam[value] = funct;
// };
exports.handler = handler;
exports.remediate = remediate;

//overrides the given function (only for jest testing)
exports.setIamFunction = (value, funct) => {
    iam[value] = funct;
 };
exports.setRemediate = (funct) => {
    callRemediate = funct;
};
