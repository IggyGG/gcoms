// @ts-nocheck
// Generated from Rust JSON schemas. Do not edit.
"use strict";
export const validRequest = validate20;
const schema31 = {"$defs":{"DecimalU64":{"pattern":"^(0|[1-9][0-9]{0,18}|18446744073709551615|1[0-7][0-9]{18}|18[0-3][0-9]{17}|184[0-3][0-9]{16}|1844[0-5][0-9]{15}|18446[0-6][0-9]{14}|184467[0-3][0-9]{13}|1844674[0-3][0-9]{12}|184467440[0-6][0-9]{10}|1844674407[0-2][0-9]{9}|18446744073[0-6][0-9]{8}|1844674407370[0-8][0-9]{6}|18446744073709[0-4][0-9]{5}|184467440737095[0-4][0-9]{4}|1844674407370955[0-0][0-9]{3}|18446744073709551[0-5][0-9]{2}|184467440737095516[0-0][0-9]{1}|1844674407370955161[0-4][0-9]{0})$","type":"string"},"Invocation":{"oneOf":[{"additionalProperties":false,"properties":{"action":{"const":"call","type":"string"},"args":true,"operation":{"anyOf":[{"$ref":"#/$defs/OperationToken"},{"type":"null"}]}},"required":["action","args"],"type":"object"},{"additionalProperties":false,"properties":{"action":{"const":"status","type":"string"},"operation_id":{"$ref":"#/$defs/OperationId"}},"required":["action","operation_id"],"type":"object"}]},"OperationId":{"maxLength":128,"minLength":16,"pattern":"^[A-Za-z0-9_-]+$","type":"string"},"OperationToken":{"additionalProperties":false,"properties":{"deadline":{"$ref":"#/$defs/DecimalU64"},"id":{"$ref":"#/$defs/OperationId"}},"required":["id","deadline"],"type":"object"}},"$schema":"https://json-schema.org/draft/2020-12/schema","additionalProperties":false,"properties":{"id":{"$ref":"#/$defs/OperationId"},"instance":{"type":"string"},"invocation":{"$ref":"#/$defs/Invocation"},"method":{"type":"string"},"rpc":{"format":"uint16","maximum":65535,"minimum":0,"type":"integer"},"service":{"type":"string"},"version":{"format":"uint16","maximum":65535,"minimum":0,"type":"integer"}},"required":["rpc","id","instance","service","version","method","invocation"],"title":"Request","type":"object"};
const schema32 = {"maxLength":128,"minLength":16,"pattern":"^[A-Za-z0-9_-]+$","type":"string"};
const func1 = value => [...value].length;
const pattern4 = new RegExp("^[A-Za-z0-9_-]+$", "u");
const schema33 = {"oneOf":[{"additionalProperties":false,"properties":{"action":{"const":"call","type":"string"},"args":true,"operation":{"anyOf":[{"$ref":"#/$defs/OperationToken"},{"type":"null"}]}},"required":["action","args"],"type":"object"},{"additionalProperties":false,"properties":{"action":{"const":"status","type":"string"},"operation_id":{"$ref":"#/$defs/OperationId"}},"required":["action","operation_id"],"type":"object"}]};
const schema34 = {"additionalProperties":false,"properties":{"deadline":{"$ref":"#/$defs/DecimalU64"},"id":{"$ref":"#/$defs/OperationId"}},"required":["id","deadline"],"type":"object"};
const schema35 = {"pattern":"^(0|[1-9][0-9]{0,18}|18446744073709551615|1[0-7][0-9]{18}|18[0-3][0-9]{17}|184[0-3][0-9]{16}|1844[0-5][0-9]{15}|18446[0-6][0-9]{14}|184467[0-3][0-9]{13}|1844674[0-3][0-9]{12}|184467440[0-6][0-9]{10}|1844674407[0-2][0-9]{9}|18446744073[0-6][0-9]{8}|1844674407370[0-8][0-9]{6}|18446744073709[0-4][0-9]{5}|184467440737095[0-4][0-9]{4}|1844674407370955[0-0][0-9]{3}|18446744073709551[0-5][0-9]{2}|184467440737095516[0-0][0-9]{1}|1844674407370955161[0-4][0-9]{0})$","type":"string"};
const pattern5 = new RegExp("^(0|[1-9][0-9]{0,18}|18446744073709551615|1[0-7][0-9]{18}|18[0-3][0-9]{17}|184[0-3][0-9]{16}|1844[0-5][0-9]{15}|18446[0-6][0-9]{14}|184467[0-3][0-9]{13}|1844674[0-3][0-9]{12}|184467440[0-6][0-9]{10}|1844674407[0-2][0-9]{9}|18446744073[0-6][0-9]{8}|1844674407370[0-8][0-9]{6}|18446744073709[0-4][0-9]{5}|184467440737095[0-4][0-9]{4}|1844674407370955[0-0][0-9]{3}|18446744073709551[0-5][0-9]{2}|184467440737095516[0-0][0-9]{1}|1844674407370955161[0-4][0-9]{0})$", "u");

function validate22(data, {instancePath="", parentData, parentDataProperty, rootData=data, dynamicAnchors={}}={}){
let vErrors = null;
let errors = 0;
const evaluated0 = validate22.evaluated;
if(evaluated0.dynamicProps){
evaluated0.props = undefined;
}
if(evaluated0.dynamicItems){
evaluated0.items = undefined;
}
if(errors === 0){
if(data && typeof data == "object" && !Array.isArray(data)){
let missing0;
if(((data.id === undefined) && (missing0 = "id")) || ((data.deadline === undefined) && (missing0 = "deadline"))){
validate22.errors = [{instancePath,schemaPath:"#/required",keyword:"required",params:{missingProperty: missing0},message:"must have required property '"+missing0+"'"}];
return false;
}
else {
const _errs1 = errors;
for(const key0 in data){
if(!((key0 === "deadline") || (key0 === "id"))){
validate22.errors = [{instancePath,schemaPath:"#/additionalProperties",keyword:"additionalProperties",params:{additionalProperty: key0},message:"must NOT have additional properties"}];
return false;
break;
}
}
if(_errs1 === errors){
if(data.deadline !== undefined){
let data0 = data.deadline;
const _errs2 = errors;
const _errs3 = errors;
if(errors === _errs3){
if(typeof data0 === "string"){
if(!pattern5.test(data0)){
validate22.errors = [{instancePath:instancePath+"/deadline",schemaPath:"#/$defs/DecimalU64/pattern",keyword:"pattern",params:{pattern: "^(0|[1-9][0-9]{0,18}|18446744073709551615|1[0-7][0-9]{18}|18[0-3][0-9]{17}|184[0-3][0-9]{16}|1844[0-5][0-9]{15}|18446[0-6][0-9]{14}|184467[0-3][0-9]{13}|1844674[0-3][0-9]{12}|184467440[0-6][0-9]{10}|1844674407[0-2][0-9]{9}|18446744073[0-6][0-9]{8}|1844674407370[0-8][0-9]{6}|18446744073709[0-4][0-9]{5}|184467440737095[0-4][0-9]{4}|1844674407370955[0-0][0-9]{3}|18446744073709551[0-5][0-9]{2}|184467440737095516[0-0][0-9]{1}|1844674407370955161[0-4][0-9]{0})$"},message:"must match pattern \""+"^(0|[1-9][0-9]{0,18}|18446744073709551615|1[0-7][0-9]{18}|18[0-3][0-9]{17}|184[0-3][0-9]{16}|1844[0-5][0-9]{15}|18446[0-6][0-9]{14}|184467[0-3][0-9]{13}|1844674[0-3][0-9]{12}|184467440[0-6][0-9]{10}|1844674407[0-2][0-9]{9}|18446744073[0-6][0-9]{8}|1844674407370[0-8][0-9]{6}|18446744073709[0-4][0-9]{5}|184467440737095[0-4][0-9]{4}|1844674407370955[0-0][0-9]{3}|18446744073709551[0-5][0-9]{2}|184467440737095516[0-0][0-9]{1}|1844674407370955161[0-4][0-9]{0})$"+"\""}];
return false;
}
}
else {
validate22.errors = [{instancePath:instancePath+"/deadline",schemaPath:"#/$defs/DecimalU64/type",keyword:"type",params:{type: "string"},message:"must be string"}];
return false;
}
}
var valid0 = _errs2 === errors;
}
else {
var valid0 = true;
}
if(valid0){
if(data.id !== undefined){
let data1 = data.id;
const _errs5 = errors;
const _errs6 = errors;
if(errors === _errs6){
if(typeof data1 === "string"){
if(func1(data1) > 128){
validate22.errors = [{instancePath:instancePath+"/id",schemaPath:"#/$defs/OperationId/maxLength",keyword:"maxLength",params:{limit: 128},message:"must NOT have more than 128 characters"}];
return false;
}
else {
if(func1(data1) < 16){
validate22.errors = [{instancePath:instancePath+"/id",schemaPath:"#/$defs/OperationId/minLength",keyword:"minLength",params:{limit: 16},message:"must NOT have fewer than 16 characters"}];
return false;
}
else {
if(!pattern4.test(data1)){
validate22.errors = [{instancePath:instancePath+"/id",schemaPath:"#/$defs/OperationId/pattern",keyword:"pattern",params:{pattern: "^[A-Za-z0-9_-]+$"},message:"must match pattern \""+"^[A-Za-z0-9_-]+$"+"\""}];
return false;
}
}
}
}
else {
validate22.errors = [{instancePath:instancePath+"/id",schemaPath:"#/$defs/OperationId/type",keyword:"type",params:{type: "string"},message:"must be string"}];
return false;
}
}
var valid0 = _errs5 === errors;
}
else {
var valid0 = true;
}
}
}
}
}
else {
validate22.errors = [{instancePath,schemaPath:"#/type",keyword:"type",params:{type: "object"},message:"must be object"}];
return false;
}
}
validate22.errors = vErrors;
return errors === 0;
}
validate22.evaluated = {"props":true,"dynamicProps":false,"dynamicItems":false};


function validate21(data, {instancePath="", parentData, parentDataProperty, rootData=data, dynamicAnchors={}}={}){
let vErrors = null;
let errors = 0;
const evaluated0 = validate21.evaluated;
if(evaluated0.dynamicProps){
evaluated0.props = undefined;
}
if(evaluated0.dynamicItems){
evaluated0.items = undefined;
}
const _errs0 = errors;
let valid0 = false;
let passing0 = null;
const _errs1 = errors;
if(errors === _errs1){
if(data && typeof data == "object" && !Array.isArray(data)){
let missing0;
if(((data.action === undefined) && (missing0 = "action")) || ((data.args === undefined) && (missing0 = "args"))){
const err0 = {instancePath,schemaPath:"#/oneOf/0/required",keyword:"required",params:{missingProperty: missing0},message:"must have required property '"+missing0+"'"};
if(vErrors === null){
vErrors = [err0];
}
else {
vErrors.push(err0);
}
errors++;
}
else {
const _errs3 = errors;
for(const key0 in data){
if(!(((key0 === "action") || (key0 === "args")) || (key0 === "operation"))){
const err1 = {instancePath,schemaPath:"#/oneOf/0/additionalProperties",keyword:"additionalProperties",params:{additionalProperty: key0},message:"must NOT have additional properties"};
if(vErrors === null){
vErrors = [err1];
}
else {
vErrors.push(err1);
}
errors++;
break;
}
}
if(_errs3 === errors){
if(data.action !== undefined){
let data0 = data.action;
const _errs4 = errors;
if(typeof data0 !== "string"){
const err2 = {instancePath:instancePath+"/action",schemaPath:"#/oneOf/0/properties/action/type",keyword:"type",params:{type: "string"},message:"must be string"};
if(vErrors === null){
vErrors = [err2];
}
else {
vErrors.push(err2);
}
errors++;
}
if("call" !== data0){
const err3 = {instancePath:instancePath+"/action",schemaPath:"#/oneOf/0/properties/action/const",keyword:"const",params:{allowedValue: "call"},message:"must be equal to constant"};
if(vErrors === null){
vErrors = [err3];
}
else {
vErrors.push(err3);
}
errors++;
}
var valid1 = _errs4 === errors;
}
else {
var valid1 = true;
}
if(valid1){
if(data.operation !== undefined){
let data1 = data.operation;
const _errs6 = errors;
const _errs7 = errors;
let valid2 = false;
const _errs8 = errors;
if(!(validate22(data1, {instancePath:instancePath+"/operation",parentData:data,parentDataProperty:"operation",rootData,dynamicAnchors}))){
vErrors = vErrors === null ? validate22.errors : vErrors.concat(validate22.errors);
errors = vErrors.length;
}
var _valid1 = _errs8 === errors;
valid2 = valid2 || _valid1;
const _errs9 = errors;
if(data1 !== null){
const err4 = {instancePath:instancePath+"/operation",schemaPath:"#/oneOf/0/properties/operation/anyOf/1/type",keyword:"type",params:{type: "null"},message:"must be null"};
if(vErrors === null){
vErrors = [err4];
}
else {
vErrors.push(err4);
}
errors++;
}
var _valid1 = _errs9 === errors;
valid2 = valid2 || _valid1;
if(!valid2){
const err5 = {instancePath:instancePath+"/operation",schemaPath:"#/oneOf/0/properties/operation/anyOf",keyword:"anyOf",params:{},message:"must match a schema in anyOf"};
if(vErrors === null){
vErrors = [err5];
}
else {
vErrors.push(err5);
}
errors++;
}
else {
errors = _errs7;
if(vErrors !== null){
if(_errs7){
vErrors.length = _errs7;
}
else {
vErrors = null;
}
}
}
var valid1 = _errs6 === errors;
}
else {
var valid1 = true;
}
}
}
}
}
else {
const err6 = {instancePath,schemaPath:"#/oneOf/0/type",keyword:"type",params:{type: "object"},message:"must be object"};
if(vErrors === null){
vErrors = [err6];
}
else {
vErrors.push(err6);
}
errors++;
}
}
var _valid0 = _errs1 === errors;
if(_valid0){
valid0 = true;
passing0 = 0;
var props1 = true;
}
const _errs11 = errors;
if(errors === _errs11){
if(data && typeof data == "object" && !Array.isArray(data)){
let missing1;
if(((data.action === undefined) && (missing1 = "action")) || ((data.operation_id === undefined) && (missing1 = "operation_id"))){
const err7 = {instancePath,schemaPath:"#/oneOf/1/required",keyword:"required",params:{missingProperty: missing1},message:"must have required property '"+missing1+"'"};
if(vErrors === null){
vErrors = [err7];
}
else {
vErrors.push(err7);
}
errors++;
}
else {
const _errs13 = errors;
for(const key1 in data){
if(!((key1 === "action") || (key1 === "operation_id"))){
const err8 = {instancePath,schemaPath:"#/oneOf/1/additionalProperties",keyword:"additionalProperties",params:{additionalProperty: key1},message:"must NOT have additional properties"};
if(vErrors === null){
vErrors = [err8];
}
else {
vErrors.push(err8);
}
errors++;
break;
}
}
if(_errs13 === errors){
if(data.action !== undefined){
let data2 = data.action;
const _errs14 = errors;
if(typeof data2 !== "string"){
const err9 = {instancePath:instancePath+"/action",schemaPath:"#/oneOf/1/properties/action/type",keyword:"type",params:{type: "string"},message:"must be string"};
if(vErrors === null){
vErrors = [err9];
}
else {
vErrors.push(err9);
}
errors++;
}
if("status" !== data2){
const err10 = {instancePath:instancePath+"/action",schemaPath:"#/oneOf/1/properties/action/const",keyword:"const",params:{allowedValue: "status"},message:"must be equal to constant"};
if(vErrors === null){
vErrors = [err10];
}
else {
vErrors.push(err10);
}
errors++;
}
var valid3 = _errs14 === errors;
}
else {
var valid3 = true;
}
if(valid3){
if(data.operation_id !== undefined){
let data3 = data.operation_id;
const _errs16 = errors;
const _errs17 = errors;
if(errors === _errs17){
if(typeof data3 === "string"){
if(func1(data3) > 128){
const err11 = {instancePath:instancePath+"/operation_id",schemaPath:"#/$defs/OperationId/maxLength",keyword:"maxLength",params:{limit: 128},message:"must NOT have more than 128 characters"};
if(vErrors === null){
vErrors = [err11];
}
else {
vErrors.push(err11);
}
errors++;
}
else {
if(func1(data3) < 16){
const err12 = {instancePath:instancePath+"/operation_id",schemaPath:"#/$defs/OperationId/minLength",keyword:"minLength",params:{limit: 16},message:"must NOT have fewer than 16 characters"};
if(vErrors === null){
vErrors = [err12];
}
else {
vErrors.push(err12);
}
errors++;
}
else {
if(!pattern4.test(data3)){
const err13 = {instancePath:instancePath+"/operation_id",schemaPath:"#/$defs/OperationId/pattern",keyword:"pattern",params:{pattern: "^[A-Za-z0-9_-]+$"},message:"must match pattern \""+"^[A-Za-z0-9_-]+$"+"\""};
if(vErrors === null){
vErrors = [err13];
}
else {
vErrors.push(err13);
}
errors++;
}
}
}
}
else {
const err14 = {instancePath:instancePath+"/operation_id",schemaPath:"#/$defs/OperationId/type",keyword:"type",params:{type: "string"},message:"must be string"};
if(vErrors === null){
vErrors = [err14];
}
else {
vErrors.push(err14);
}
errors++;
}
}
var valid3 = _errs16 === errors;
}
else {
var valid3 = true;
}
}
}
}
}
else {
const err15 = {instancePath,schemaPath:"#/oneOf/1/type",keyword:"type",params:{type: "object"},message:"must be object"};
if(vErrors === null){
vErrors = [err15];
}
else {
vErrors.push(err15);
}
errors++;
}
}
var _valid0 = _errs11 === errors;
if(_valid0 && valid0){
valid0 = false;
passing0 = [passing0, 1];
}
else {
if(_valid0){
valid0 = true;
passing0 = 1;
if(props1 !== true){
props1 = true;
}
}
}
if(!valid0){
const err16 = {instancePath,schemaPath:"#/oneOf",keyword:"oneOf",params:{passingSchemas: passing0},message:"must match exactly one schema in oneOf"};
if(vErrors === null){
vErrors = [err16];
}
else {
vErrors.push(err16);
}
errors++;
validate21.errors = vErrors;
return false;
}
else {
errors = _errs0;
if(vErrors !== null){
if(_errs0){
vErrors.length = _errs0;
}
else {
vErrors = null;
}
}
}
validate21.errors = vErrors;
evaluated0.props = props1;
return errors === 0;
}
validate21.evaluated = {"dynamicProps":true,"dynamicItems":false};


function validate20(data, {instancePath="", parentData, parentDataProperty, rootData=data, dynamicAnchors={}}={}){
let vErrors = null;
let errors = 0;
const evaluated0 = validate20.evaluated;
if(evaluated0.dynamicProps){
evaluated0.props = undefined;
}
if(evaluated0.dynamicItems){
evaluated0.items = undefined;
}
if(errors === 0){
if(data && typeof data == "object" && !Array.isArray(data)){
let missing0;
if((((((((data.rpc === undefined) && (missing0 = "rpc")) || ((data.id === undefined) && (missing0 = "id"))) || ((data.instance === undefined) && (missing0 = "instance"))) || ((data.service === undefined) && (missing0 = "service"))) || ((data.version === undefined) && (missing0 = "version"))) || ((data.method === undefined) && (missing0 = "method"))) || ((data.invocation === undefined) && (missing0 = "invocation"))){
validate20.errors = [{instancePath,schemaPath:"#/required",keyword:"required",params:{missingProperty: missing0},message:"must have required property '"+missing0+"'"}];
return false;
}
else {
const _errs1 = errors;
for(const key0 in data){
if(!(((((((key0 === "id") || (key0 === "instance")) || (key0 === "invocation")) || (key0 === "method")) || (key0 === "rpc")) || (key0 === "service")) || (key0 === "version"))){
validate20.errors = [{instancePath,schemaPath:"#/additionalProperties",keyword:"additionalProperties",params:{additionalProperty: key0},message:"must NOT have additional properties"}];
return false;
break;
}
}
if(_errs1 === errors){
if(data.id !== undefined){
let data0 = data.id;
const _errs2 = errors;
const _errs3 = errors;
if(errors === _errs3){
if(typeof data0 === "string"){
if(func1(data0) > 128){
validate20.errors = [{instancePath:instancePath+"/id",schemaPath:"#/$defs/OperationId/maxLength",keyword:"maxLength",params:{limit: 128},message:"must NOT have more than 128 characters"}];
return false;
}
else {
if(func1(data0) < 16){
validate20.errors = [{instancePath:instancePath+"/id",schemaPath:"#/$defs/OperationId/minLength",keyword:"minLength",params:{limit: 16},message:"must NOT have fewer than 16 characters"}];
return false;
}
else {
if(!pattern4.test(data0)){
validate20.errors = [{instancePath:instancePath+"/id",schemaPath:"#/$defs/OperationId/pattern",keyword:"pattern",params:{pattern: "^[A-Za-z0-9_-]+$"},message:"must match pattern \""+"^[A-Za-z0-9_-]+$"+"\""}];
return false;
}
}
}
}
else {
validate20.errors = [{instancePath:instancePath+"/id",schemaPath:"#/$defs/OperationId/type",keyword:"type",params:{type: "string"},message:"must be string"}];
return false;
}
}
var valid0 = _errs2 === errors;
}
else {
var valid0 = true;
}
if(valid0){
if(data.instance !== undefined){
const _errs5 = errors;
if(typeof data.instance !== "string"){
validate20.errors = [{instancePath:instancePath+"/instance",schemaPath:"#/properties/instance/type",keyword:"type",params:{type: "string"},message:"must be string"}];
return false;
}
var valid0 = _errs5 === errors;
}
else {
var valid0 = true;
}
if(valid0){
if(data.invocation !== undefined){
const _errs7 = errors;
if(!(validate21(data.invocation, {instancePath:instancePath+"/invocation",parentData:data,parentDataProperty:"invocation",rootData,dynamicAnchors}))){
vErrors = vErrors === null ? validate21.errors : vErrors.concat(validate21.errors);
errors = vErrors.length;
}
var valid0 = _errs7 === errors;
}
else {
var valid0 = true;
}
if(valid0){
if(data.method !== undefined){
const _errs8 = errors;
if(typeof data.method !== "string"){
validate20.errors = [{instancePath:instancePath+"/method",schemaPath:"#/properties/method/type",keyword:"type",params:{type: "string"},message:"must be string"}];
return false;
}
var valid0 = _errs8 === errors;
}
else {
var valid0 = true;
}
if(valid0){
if(data.rpc !== undefined){
let data4 = data.rpc;
const _errs10 = errors;
if(!(((typeof data4 == "number") && (!(data4 % 1) && !isNaN(data4))) && (isFinite(data4)))){
validate20.errors = [{instancePath:instancePath+"/rpc",schemaPath:"#/properties/rpc/type",keyword:"type",params:{type: "integer"},message:"must be integer"}];
return false;
}
if(errors === _errs10){
if((typeof data4 == "number") && (isFinite(data4))){
if(data4 > 65535 || isNaN(data4)){
validate20.errors = [{instancePath:instancePath+"/rpc",schemaPath:"#/properties/rpc/maximum",keyword:"maximum",params:{comparison: "<=", limit: 65535},message:"must be <= 65535"}];
return false;
}
else {
if(data4 < 0 || isNaN(data4)){
validate20.errors = [{instancePath:instancePath+"/rpc",schemaPath:"#/properties/rpc/minimum",keyword:"minimum",params:{comparison: ">=", limit: 0},message:"must be >= 0"}];
return false;
}
}
}
}
var valid0 = _errs10 === errors;
}
else {
var valid0 = true;
}
if(valid0){
if(data.service !== undefined){
const _errs12 = errors;
if(typeof data.service !== "string"){
validate20.errors = [{instancePath:instancePath+"/service",schemaPath:"#/properties/service/type",keyword:"type",params:{type: "string"},message:"must be string"}];
return false;
}
var valid0 = _errs12 === errors;
}
else {
var valid0 = true;
}
if(valid0){
if(data.version !== undefined){
let data6 = data.version;
const _errs14 = errors;
if(!(((typeof data6 == "number") && (!(data6 % 1) && !isNaN(data6))) && (isFinite(data6)))){
validate20.errors = [{instancePath:instancePath+"/version",schemaPath:"#/properties/version/type",keyword:"type",params:{type: "integer"},message:"must be integer"}];
return false;
}
if(errors === _errs14){
if((typeof data6 == "number") && (isFinite(data6))){
if(data6 > 65535 || isNaN(data6)){
validate20.errors = [{instancePath:instancePath+"/version",schemaPath:"#/properties/version/maximum",keyword:"maximum",params:{comparison: "<=", limit: 65535},message:"must be <= 65535"}];
return false;
}
else {
if(data6 < 0 || isNaN(data6)){
validate20.errors = [{instancePath:instancePath+"/version",schemaPath:"#/properties/version/minimum",keyword:"minimum",params:{comparison: ">=", limit: 0},message:"must be >= 0"}];
return false;
}
}
}
}
var valid0 = _errs14 === errors;
}
else {
var valid0 = true;
}
}
}
}
}
}
}
}
}
}
else {
validate20.errors = [{instancePath,schemaPath:"#/type",keyword:"type",params:{type: "object"},message:"must be object"}];
return false;
}
}
validate20.errors = vErrors;
return errors === 0;
}
validate20.evaluated = {"props":true,"dynamicProps":false,"dynamicItems":false};

export const validReply = validate25;
const schema38 = {"$defs":{"ErrorCode":{"enum":["invalid_request","version","instance","service","method","unauthorized","conflict","expired","unavailable","busy","payload_too_large","storage","transport","timeout","protocol"],"type":"string"},"OperationId":{"maxLength":128,"minLength":16,"pattern":"^[A-Za-z0-9_-]+$","type":"string"},"Outcome":{"oneOf":[{"additionalProperties":false,"properties":{"kind":{"const":"ok","type":"string"},"value":true},"required":["kind","value"],"type":"object"},{"additionalProperties":false,"properties":{"kind":{"const":"error","type":"string"},"value":true},"required":["kind","value"],"type":"object"}]},"ReplyBody":{"oneOf":[{"additionalProperties":false,"properties":{"outcome":{"$ref":"#/$defs/Outcome"},"state":{"const":"done","type":"string"}},"required":["state","outcome"],"type":"object"},{"additionalProperties":false,"properties":{"state":{"const":"running","type":"string"}},"required":["state"],"type":"object"},{"additionalProperties":false,"properties":{"state":{"const":"outcome_unknown","type":"string"}},"required":["state"],"type":"object"},{"additionalProperties":false,"properties":{"state":{"const":"unavailable","type":"string"}},"required":["state"],"type":"object"},{"additionalProperties":false,"properties":{"error":{"$ref":"#/$defs/RpcError"},"state":{"const":"failed","type":"string"}},"required":["state","error"],"type":"object"}]},"RpcError":{"additionalProperties":false,"properties":{"code":{"$ref":"#/$defs/ErrorCode"},"message":{"type":"string"}},"required":["code","message"],"type":"object"}},"$schema":"https://json-schema.org/draft/2020-12/schema","additionalProperties":false,"properties":{"body":{"$ref":"#/$defs/ReplyBody"},"id":{"$ref":"#/$defs/OperationId"},"instance":{"type":"string"},"method":{"type":"string"},"rpc":{"format":"uint16","maximum":65535,"minimum":0,"type":"integer"},"service":{"type":"string"},"version":{"format":"uint16","maximum":65535,"minimum":0,"type":"integer"}},"required":["rpc","id","instance","service","version","method","body"],"title":"Reply","type":"object"};
const schema43 = {"maxLength":128,"minLength":16,"pattern":"^[A-Za-z0-9_-]+$","type":"string"};
const schema39 = {"oneOf":[{"additionalProperties":false,"properties":{"outcome":{"$ref":"#/$defs/Outcome"},"state":{"const":"done","type":"string"}},"required":["state","outcome"],"type":"object"},{"additionalProperties":false,"properties":{"state":{"const":"running","type":"string"}},"required":["state"],"type":"object"},{"additionalProperties":false,"properties":{"state":{"const":"outcome_unknown","type":"string"}},"required":["state"],"type":"object"},{"additionalProperties":false,"properties":{"state":{"const":"unavailable","type":"string"}},"required":["state"],"type":"object"},{"additionalProperties":false,"properties":{"error":{"$ref":"#/$defs/RpcError"},"state":{"const":"failed","type":"string"}},"required":["state","error"],"type":"object"}]};
const schema40 = {"oneOf":[{"additionalProperties":false,"properties":{"kind":{"const":"ok","type":"string"},"value":true},"required":["kind","value"],"type":"object"},{"additionalProperties":false,"properties":{"kind":{"const":"error","type":"string"},"value":true},"required":["kind","value"],"type":"object"}]};
const schema41 = {"additionalProperties":false,"properties":{"code":{"$ref":"#/$defs/ErrorCode"},"message":{"type":"string"}},"required":["code","message"],"type":"object"};
const schema42 = {"enum":["invalid_request","version","instance","service","method","unauthorized","conflict","expired","unavailable","busy","payload_too_large","storage","transport","timeout","protocol"],"type":"string"};

function validate27(data, {instancePath="", parentData, parentDataProperty, rootData=data, dynamicAnchors={}}={}){
let vErrors = null;
let errors = 0;
const evaluated0 = validate27.evaluated;
if(evaluated0.dynamicProps){
evaluated0.props = undefined;
}
if(evaluated0.dynamicItems){
evaluated0.items = undefined;
}
if(errors === 0){
if(data && typeof data == "object" && !Array.isArray(data)){
let missing0;
if(((data.code === undefined) && (missing0 = "code")) || ((data.message === undefined) && (missing0 = "message"))){
validate27.errors = [{instancePath,schemaPath:"#/required",keyword:"required",params:{missingProperty: missing0},message:"must have required property '"+missing0+"'"}];
return false;
}
else {
const _errs1 = errors;
for(const key0 in data){
if(!((key0 === "code") || (key0 === "message"))){
validate27.errors = [{instancePath,schemaPath:"#/additionalProperties",keyword:"additionalProperties",params:{additionalProperty: key0},message:"must NOT have additional properties"}];
return false;
break;
}
}
if(_errs1 === errors){
if(data.code !== undefined){
let data0 = data.code;
const _errs2 = errors;
if(typeof data0 !== "string"){
validate27.errors = [{instancePath:instancePath+"/code",schemaPath:"#/$defs/ErrorCode/type",keyword:"type",params:{type: "string"},message:"must be string"}];
return false;
}
if(!(((((((((((((((data0 === "invalid_request") || (data0 === "version")) || (data0 === "instance")) || (data0 === "service")) || (data0 === "method")) || (data0 === "unauthorized")) || (data0 === "conflict")) || (data0 === "expired")) || (data0 === "unavailable")) || (data0 === "busy")) || (data0 === "payload_too_large")) || (data0 === "storage")) || (data0 === "transport")) || (data0 === "timeout")) || (data0 === "protocol"))){
validate27.errors = [{instancePath:instancePath+"/code",schemaPath:"#/$defs/ErrorCode/enum",keyword:"enum",params:{allowedValues: schema42.enum},message:"must be equal to one of the allowed values"}];
return false;
}
var valid0 = _errs2 === errors;
}
else {
var valid0 = true;
}
if(valid0){
if(data.message !== undefined){
const _errs5 = errors;
if(typeof data.message !== "string"){
validate27.errors = [{instancePath:instancePath+"/message",schemaPath:"#/properties/message/type",keyword:"type",params:{type: "string"},message:"must be string"}];
return false;
}
var valid0 = _errs5 === errors;
}
else {
var valid0 = true;
}
}
}
}
}
else {
validate27.errors = [{instancePath,schemaPath:"#/type",keyword:"type",params:{type: "object"},message:"must be object"}];
return false;
}
}
validate27.errors = vErrors;
return errors === 0;
}
validate27.evaluated = {"props":true,"dynamicProps":false,"dynamicItems":false};


function validate26(data, {instancePath="", parentData, parentDataProperty, rootData=data, dynamicAnchors={}}={}){
let vErrors = null;
let errors = 0;
const evaluated0 = validate26.evaluated;
if(evaluated0.dynamicProps){
evaluated0.props = undefined;
}
if(evaluated0.dynamicItems){
evaluated0.items = undefined;
}
const _errs0 = errors;
let valid0 = false;
let passing0 = null;
const _errs1 = errors;
if(errors === _errs1){
if(data && typeof data == "object" && !Array.isArray(data)){
let missing0;
if(((data.state === undefined) && (missing0 = "state")) || ((data.outcome === undefined) && (missing0 = "outcome"))){
const err0 = {instancePath,schemaPath:"#/oneOf/0/required",keyword:"required",params:{missingProperty: missing0},message:"must have required property '"+missing0+"'"};
if(vErrors === null){
vErrors = [err0];
}
else {
vErrors.push(err0);
}
errors++;
}
else {
const _errs3 = errors;
for(const key0 in data){
if(!((key0 === "outcome") || (key0 === "state"))){
const err1 = {instancePath,schemaPath:"#/oneOf/0/additionalProperties",keyword:"additionalProperties",params:{additionalProperty: key0},message:"must NOT have additional properties"};
if(vErrors === null){
vErrors = [err1];
}
else {
vErrors.push(err1);
}
errors++;
break;
}
}
if(_errs3 === errors){
if(data.outcome !== undefined){
let data0 = data.outcome;
const _errs4 = errors;
const _errs6 = errors;
let valid3 = false;
let passing1 = null;
const _errs7 = errors;
if(errors === _errs7){
if(data0 && typeof data0 == "object" && !Array.isArray(data0)){
let missing1;
if(((data0.kind === undefined) && (missing1 = "kind")) || ((data0.value === undefined) && (missing1 = "value"))){
const err2 = {instancePath:instancePath+"/outcome",schemaPath:"#/$defs/Outcome/oneOf/0/required",keyword:"required",params:{missingProperty: missing1},message:"must have required property '"+missing1+"'"};
if(vErrors === null){
vErrors = [err2];
}
else {
vErrors.push(err2);
}
errors++;
}
else {
const _errs9 = errors;
for(const key1 in data0){
if(!((key1 === "kind") || (key1 === "value"))){
const err3 = {instancePath:instancePath+"/outcome",schemaPath:"#/$defs/Outcome/oneOf/0/additionalProperties",keyword:"additionalProperties",params:{additionalProperty: key1},message:"must NOT have additional properties"};
if(vErrors === null){
vErrors = [err3];
}
else {
vErrors.push(err3);
}
errors++;
break;
}
}
if(_errs9 === errors){
if(data0.kind !== undefined){
let data1 = data0.kind;
if(typeof data1 !== "string"){
const err4 = {instancePath:instancePath+"/outcome/kind",schemaPath:"#/$defs/Outcome/oneOf/0/properties/kind/type",keyword:"type",params:{type: "string"},message:"must be string"};
if(vErrors === null){
vErrors = [err4];
}
else {
vErrors.push(err4);
}
errors++;
}
if("ok" !== data1){
const err5 = {instancePath:instancePath+"/outcome/kind",schemaPath:"#/$defs/Outcome/oneOf/0/properties/kind/const",keyword:"const",params:{allowedValue: "ok"},message:"must be equal to constant"};
if(vErrors === null){
vErrors = [err5];
}
else {
vErrors.push(err5);
}
errors++;
}
}
}
}
}
else {
const err6 = {instancePath:instancePath+"/outcome",schemaPath:"#/$defs/Outcome/oneOf/0/type",keyword:"type",params:{type: "object"},message:"must be object"};
if(vErrors === null){
vErrors = [err6];
}
else {
vErrors.push(err6);
}
errors++;
}
}
var _valid1 = _errs7 === errors;
if(_valid1){
valid3 = true;
passing1 = 0;
var props0 = true;
}
const _errs12 = errors;
if(errors === _errs12){
if(data0 && typeof data0 == "object" && !Array.isArray(data0)){
let missing2;
if(((data0.kind === undefined) && (missing2 = "kind")) || ((data0.value === undefined) && (missing2 = "value"))){
const err7 = {instancePath:instancePath+"/outcome",schemaPath:"#/$defs/Outcome/oneOf/1/required",keyword:"required",params:{missingProperty: missing2},message:"must have required property '"+missing2+"'"};
if(vErrors === null){
vErrors = [err7];
}
else {
vErrors.push(err7);
}
errors++;
}
else {
const _errs14 = errors;
for(const key2 in data0){
if(!((key2 === "kind") || (key2 === "value"))){
const err8 = {instancePath:instancePath+"/outcome",schemaPath:"#/$defs/Outcome/oneOf/1/additionalProperties",keyword:"additionalProperties",params:{additionalProperty: key2},message:"must NOT have additional properties"};
if(vErrors === null){
vErrors = [err8];
}
else {
vErrors.push(err8);
}
errors++;
break;
}
}
if(_errs14 === errors){
if(data0.kind !== undefined){
let data2 = data0.kind;
if(typeof data2 !== "string"){
const err9 = {instancePath:instancePath+"/outcome/kind",schemaPath:"#/$defs/Outcome/oneOf/1/properties/kind/type",keyword:"type",params:{type: "string"},message:"must be string"};
if(vErrors === null){
vErrors = [err9];
}
else {
vErrors.push(err9);
}
errors++;
}
if("error" !== data2){
const err10 = {instancePath:instancePath+"/outcome/kind",schemaPath:"#/$defs/Outcome/oneOf/1/properties/kind/const",keyword:"const",params:{allowedValue: "error"},message:"must be equal to constant"};
if(vErrors === null){
vErrors = [err10];
}
else {
vErrors.push(err10);
}
errors++;
}
}
}
}
}
else {
const err11 = {instancePath:instancePath+"/outcome",schemaPath:"#/$defs/Outcome/oneOf/1/type",keyword:"type",params:{type: "object"},message:"must be object"};
if(vErrors === null){
vErrors = [err11];
}
else {
vErrors.push(err11);
}
errors++;
}
}
var _valid1 = _errs12 === errors;
if(_valid1 && valid3){
valid3 = false;
passing1 = [passing1, 1];
}
else {
if(_valid1){
valid3 = true;
passing1 = 1;
if(props0 !== true){
props0 = true;
}
}
}
if(!valid3){
const err12 = {instancePath:instancePath+"/outcome",schemaPath:"#/$defs/Outcome/oneOf",keyword:"oneOf",params:{passingSchemas: passing1},message:"must match exactly one schema in oneOf"};
if(vErrors === null){
vErrors = [err12];
}
else {
vErrors.push(err12);
}
errors++;
}
else {
errors = _errs6;
if(vErrors !== null){
if(_errs6){
vErrors.length = _errs6;
}
else {
vErrors = null;
}
}
}
var valid1 = _errs4 === errors;
}
else {
var valid1 = true;
}
if(valid1){
if(data.state !== undefined){
let data3 = data.state;
const _errs17 = errors;
if(typeof data3 !== "string"){
const err13 = {instancePath:instancePath+"/state",schemaPath:"#/oneOf/0/properties/state/type",keyword:"type",params:{type: "string"},message:"must be string"};
if(vErrors === null){
vErrors = [err13];
}
else {
vErrors.push(err13);
}
errors++;
}
if("done" !== data3){
const err14 = {instancePath:instancePath+"/state",schemaPath:"#/oneOf/0/properties/state/const",keyword:"const",params:{allowedValue: "done"},message:"must be equal to constant"};
if(vErrors === null){
vErrors = [err14];
}
else {
vErrors.push(err14);
}
errors++;
}
var valid1 = _errs17 === errors;
}
else {
var valid1 = true;
}
}
}
}
}
else {
const err15 = {instancePath,schemaPath:"#/oneOf/0/type",keyword:"type",params:{type: "object"},message:"must be object"};
if(vErrors === null){
vErrors = [err15];
}
else {
vErrors.push(err15);
}
errors++;
}
}
var _valid0 = _errs1 === errors;
if(_valid0){
valid0 = true;
passing0 = 0;
var props1 = true;
}
const _errs19 = errors;
if(errors === _errs19){
if(data && typeof data == "object" && !Array.isArray(data)){
let missing3;
if((data.state === undefined) && (missing3 = "state")){
const err16 = {instancePath,schemaPath:"#/oneOf/1/required",keyword:"required",params:{missingProperty: missing3},message:"must have required property '"+missing3+"'"};
if(vErrors === null){
vErrors = [err16];
}
else {
vErrors.push(err16);
}
errors++;
}
else {
const _errs21 = errors;
for(const key3 in data){
if(!(key3 === "state")){
const err17 = {instancePath,schemaPath:"#/oneOf/1/additionalProperties",keyword:"additionalProperties",params:{additionalProperty: key3},message:"must NOT have additional properties"};
if(vErrors === null){
vErrors = [err17];
}
else {
vErrors.push(err17);
}
errors++;
break;
}
}
if(_errs21 === errors){
if(data.state !== undefined){
let data4 = data.state;
if(typeof data4 !== "string"){
const err18 = {instancePath:instancePath+"/state",schemaPath:"#/oneOf/1/properties/state/type",keyword:"type",params:{type: "string"},message:"must be string"};
if(vErrors === null){
vErrors = [err18];
}
else {
vErrors.push(err18);
}
errors++;
}
if("running" !== data4){
const err19 = {instancePath:instancePath+"/state",schemaPath:"#/oneOf/1/properties/state/const",keyword:"const",params:{allowedValue: "running"},message:"must be equal to constant"};
if(vErrors === null){
vErrors = [err19];
}
else {
vErrors.push(err19);
}
errors++;
}
}
}
}
}
else {
const err20 = {instancePath,schemaPath:"#/oneOf/1/type",keyword:"type",params:{type: "object"},message:"must be object"};
if(vErrors === null){
vErrors = [err20];
}
else {
vErrors.push(err20);
}
errors++;
}
}
var _valid0 = _errs19 === errors;
if(_valid0 && valid0){
valid0 = false;
passing0 = [passing0, 1];
}
else {
if(_valid0){
valid0 = true;
passing0 = 1;
if(props1 !== true){
props1 = true;
}
}
const _errs24 = errors;
if(errors === _errs24){
if(data && typeof data == "object" && !Array.isArray(data)){
let missing4;
if((data.state === undefined) && (missing4 = "state")){
const err21 = {instancePath,schemaPath:"#/oneOf/2/required",keyword:"required",params:{missingProperty: missing4},message:"must have required property '"+missing4+"'"};
if(vErrors === null){
vErrors = [err21];
}
else {
vErrors.push(err21);
}
errors++;
}
else {
const _errs26 = errors;
for(const key4 in data){
if(!(key4 === "state")){
const err22 = {instancePath,schemaPath:"#/oneOf/2/additionalProperties",keyword:"additionalProperties",params:{additionalProperty: key4},message:"must NOT have additional properties"};
if(vErrors === null){
vErrors = [err22];
}
else {
vErrors.push(err22);
}
errors++;
break;
}
}
if(_errs26 === errors){
if(data.state !== undefined){
let data5 = data.state;
if(typeof data5 !== "string"){
const err23 = {instancePath:instancePath+"/state",schemaPath:"#/oneOf/2/properties/state/type",keyword:"type",params:{type: "string"},message:"must be string"};
if(vErrors === null){
vErrors = [err23];
}
else {
vErrors.push(err23);
}
errors++;
}
if("outcome_unknown" !== data5){
const err24 = {instancePath:instancePath+"/state",schemaPath:"#/oneOf/2/properties/state/const",keyword:"const",params:{allowedValue: "outcome_unknown"},message:"must be equal to constant"};
if(vErrors === null){
vErrors = [err24];
}
else {
vErrors.push(err24);
}
errors++;
}
}
}
}
}
else {
const err25 = {instancePath,schemaPath:"#/oneOf/2/type",keyword:"type",params:{type: "object"},message:"must be object"};
if(vErrors === null){
vErrors = [err25];
}
else {
vErrors.push(err25);
}
errors++;
}
}
var _valid0 = _errs24 === errors;
if(_valid0 && valid0){
valid0 = false;
passing0 = [passing0, 2];
}
else {
if(_valid0){
valid0 = true;
passing0 = 2;
if(props1 !== true){
props1 = true;
}
}
const _errs29 = errors;
if(errors === _errs29){
if(data && typeof data == "object" && !Array.isArray(data)){
let missing5;
if((data.state === undefined) && (missing5 = "state")){
const err26 = {instancePath,schemaPath:"#/oneOf/3/required",keyword:"required",params:{missingProperty: missing5},message:"must have required property '"+missing5+"'"};
if(vErrors === null){
vErrors = [err26];
}
else {
vErrors.push(err26);
}
errors++;
}
else {
const _errs31 = errors;
for(const key5 in data){
if(!(key5 === "state")){
const err27 = {instancePath,schemaPath:"#/oneOf/3/additionalProperties",keyword:"additionalProperties",params:{additionalProperty: key5},message:"must NOT have additional properties"};
if(vErrors === null){
vErrors = [err27];
}
else {
vErrors.push(err27);
}
errors++;
break;
}
}
if(_errs31 === errors){
if(data.state !== undefined){
let data6 = data.state;
if(typeof data6 !== "string"){
const err28 = {instancePath:instancePath+"/state",schemaPath:"#/oneOf/3/properties/state/type",keyword:"type",params:{type: "string"},message:"must be string"};
if(vErrors === null){
vErrors = [err28];
}
else {
vErrors.push(err28);
}
errors++;
}
if("unavailable" !== data6){
const err29 = {instancePath:instancePath+"/state",schemaPath:"#/oneOf/3/properties/state/const",keyword:"const",params:{allowedValue: "unavailable"},message:"must be equal to constant"};
if(vErrors === null){
vErrors = [err29];
}
else {
vErrors.push(err29);
}
errors++;
}
}
}
}
}
else {
const err30 = {instancePath,schemaPath:"#/oneOf/3/type",keyword:"type",params:{type: "object"},message:"must be object"};
if(vErrors === null){
vErrors = [err30];
}
else {
vErrors.push(err30);
}
errors++;
}
}
var _valid0 = _errs29 === errors;
if(_valid0 && valid0){
valid0 = false;
passing0 = [passing0, 3];
}
else {
if(_valid0){
valid0 = true;
passing0 = 3;
if(props1 !== true){
props1 = true;
}
}
const _errs34 = errors;
if(errors === _errs34){
if(data && typeof data == "object" && !Array.isArray(data)){
let missing6;
if(((data.state === undefined) && (missing6 = "state")) || ((data.error === undefined) && (missing6 = "error"))){
const err31 = {instancePath,schemaPath:"#/oneOf/4/required",keyword:"required",params:{missingProperty: missing6},message:"must have required property '"+missing6+"'"};
if(vErrors === null){
vErrors = [err31];
}
else {
vErrors.push(err31);
}
errors++;
}
else {
const _errs36 = errors;
for(const key6 in data){
if(!((key6 === "error") || (key6 === "state"))){
const err32 = {instancePath,schemaPath:"#/oneOf/4/additionalProperties",keyword:"additionalProperties",params:{additionalProperty: key6},message:"must NOT have additional properties"};
if(vErrors === null){
vErrors = [err32];
}
else {
vErrors.push(err32);
}
errors++;
break;
}
}
if(_errs36 === errors){
if(data.error !== undefined){
const _errs37 = errors;
if(!(validate27(data.error, {instancePath:instancePath+"/error",parentData:data,parentDataProperty:"error",rootData,dynamicAnchors}))){
vErrors = vErrors === null ? validate27.errors : vErrors.concat(validate27.errors);
errors = vErrors.length;
}
var valid9 = _errs37 === errors;
}
else {
var valid9 = true;
}
if(valid9){
if(data.state !== undefined){
let data8 = data.state;
const _errs38 = errors;
if(typeof data8 !== "string"){
const err33 = {instancePath:instancePath+"/state",schemaPath:"#/oneOf/4/properties/state/type",keyword:"type",params:{type: "string"},message:"must be string"};
if(vErrors === null){
vErrors = [err33];
}
else {
vErrors.push(err33);
}
errors++;
}
if("failed" !== data8){
const err34 = {instancePath:instancePath+"/state",schemaPath:"#/oneOf/4/properties/state/const",keyword:"const",params:{allowedValue: "failed"},message:"must be equal to constant"};
if(vErrors === null){
vErrors = [err34];
}
else {
vErrors.push(err34);
}
errors++;
}
var valid9 = _errs38 === errors;
}
else {
var valid9 = true;
}
}
}
}
}
else {
const err35 = {instancePath,schemaPath:"#/oneOf/4/type",keyword:"type",params:{type: "object"},message:"must be object"};
if(vErrors === null){
vErrors = [err35];
}
else {
vErrors.push(err35);
}
errors++;
}
}
var _valid0 = _errs34 === errors;
if(_valid0 && valid0){
valid0 = false;
passing0 = [passing0, 4];
}
else {
if(_valid0){
valid0 = true;
passing0 = 4;
if(props1 !== true){
props1 = true;
}
}
}
}
}
}
if(!valid0){
const err36 = {instancePath,schemaPath:"#/oneOf",keyword:"oneOf",params:{passingSchemas: passing0},message:"must match exactly one schema in oneOf"};
if(vErrors === null){
vErrors = [err36];
}
else {
vErrors.push(err36);
}
errors++;
validate26.errors = vErrors;
return false;
}
else {
errors = _errs0;
if(vErrors !== null){
if(_errs0){
vErrors.length = _errs0;
}
else {
vErrors = null;
}
}
}
validate26.errors = vErrors;
evaluated0.props = props1;
return errors === 0;
}
validate26.evaluated = {"dynamicProps":true,"dynamicItems":false};


function validate25(data, {instancePath="", parentData, parentDataProperty, rootData=data, dynamicAnchors={}}={}){
let vErrors = null;
let errors = 0;
const evaluated0 = validate25.evaluated;
if(evaluated0.dynamicProps){
evaluated0.props = undefined;
}
if(evaluated0.dynamicItems){
evaluated0.items = undefined;
}
if(errors === 0){
if(data && typeof data == "object" && !Array.isArray(data)){
let missing0;
if((((((((data.rpc === undefined) && (missing0 = "rpc")) || ((data.id === undefined) && (missing0 = "id"))) || ((data.instance === undefined) && (missing0 = "instance"))) || ((data.service === undefined) && (missing0 = "service"))) || ((data.version === undefined) && (missing0 = "version"))) || ((data.method === undefined) && (missing0 = "method"))) || ((data.body === undefined) && (missing0 = "body"))){
validate25.errors = [{instancePath,schemaPath:"#/required",keyword:"required",params:{missingProperty: missing0},message:"must have required property '"+missing0+"'"}];
return false;
}
else {
const _errs1 = errors;
for(const key0 in data){
if(!(((((((key0 === "body") || (key0 === "id")) || (key0 === "instance")) || (key0 === "method")) || (key0 === "rpc")) || (key0 === "service")) || (key0 === "version"))){
validate25.errors = [{instancePath,schemaPath:"#/additionalProperties",keyword:"additionalProperties",params:{additionalProperty: key0},message:"must NOT have additional properties"}];
return false;
break;
}
}
if(_errs1 === errors){
if(data.body !== undefined){
const _errs2 = errors;
if(!(validate26(data.body, {instancePath:instancePath+"/body",parentData:data,parentDataProperty:"body",rootData,dynamicAnchors}))){
vErrors = vErrors === null ? validate26.errors : vErrors.concat(validate26.errors);
errors = vErrors.length;
}
var valid0 = _errs2 === errors;
}
else {
var valid0 = true;
}
if(valid0){
if(data.id !== undefined){
let data1 = data.id;
const _errs3 = errors;
const _errs4 = errors;
if(errors === _errs4){
if(typeof data1 === "string"){
if(func1(data1) > 128){
validate25.errors = [{instancePath:instancePath+"/id",schemaPath:"#/$defs/OperationId/maxLength",keyword:"maxLength",params:{limit: 128},message:"must NOT have more than 128 characters"}];
return false;
}
else {
if(func1(data1) < 16){
validate25.errors = [{instancePath:instancePath+"/id",schemaPath:"#/$defs/OperationId/minLength",keyword:"minLength",params:{limit: 16},message:"must NOT have fewer than 16 characters"}];
return false;
}
else {
if(!pattern4.test(data1)){
validate25.errors = [{instancePath:instancePath+"/id",schemaPath:"#/$defs/OperationId/pattern",keyword:"pattern",params:{pattern: "^[A-Za-z0-9_-]+$"},message:"must match pattern \""+"^[A-Za-z0-9_-]+$"+"\""}];
return false;
}
}
}
}
else {
validate25.errors = [{instancePath:instancePath+"/id",schemaPath:"#/$defs/OperationId/type",keyword:"type",params:{type: "string"},message:"must be string"}];
return false;
}
}
var valid0 = _errs3 === errors;
}
else {
var valid0 = true;
}
if(valid0){
if(data.instance !== undefined){
const _errs6 = errors;
if(typeof data.instance !== "string"){
validate25.errors = [{instancePath:instancePath+"/instance",schemaPath:"#/properties/instance/type",keyword:"type",params:{type: "string"},message:"must be string"}];
return false;
}
var valid0 = _errs6 === errors;
}
else {
var valid0 = true;
}
if(valid0){
if(data.method !== undefined){
const _errs8 = errors;
if(typeof data.method !== "string"){
validate25.errors = [{instancePath:instancePath+"/method",schemaPath:"#/properties/method/type",keyword:"type",params:{type: "string"},message:"must be string"}];
return false;
}
var valid0 = _errs8 === errors;
}
else {
var valid0 = true;
}
if(valid0){
if(data.rpc !== undefined){
let data4 = data.rpc;
const _errs10 = errors;
if(!(((typeof data4 == "number") && (!(data4 % 1) && !isNaN(data4))) && (isFinite(data4)))){
validate25.errors = [{instancePath:instancePath+"/rpc",schemaPath:"#/properties/rpc/type",keyword:"type",params:{type: "integer"},message:"must be integer"}];
return false;
}
if(errors === _errs10){
if((typeof data4 == "number") && (isFinite(data4))){
if(data4 > 65535 || isNaN(data4)){
validate25.errors = [{instancePath:instancePath+"/rpc",schemaPath:"#/properties/rpc/maximum",keyword:"maximum",params:{comparison: "<=", limit: 65535},message:"must be <= 65535"}];
return false;
}
else {
if(data4 < 0 || isNaN(data4)){
validate25.errors = [{instancePath:instancePath+"/rpc",schemaPath:"#/properties/rpc/minimum",keyword:"minimum",params:{comparison: ">=", limit: 0},message:"must be >= 0"}];
return false;
}
}
}
}
var valid0 = _errs10 === errors;
}
else {
var valid0 = true;
}
if(valid0){
if(data.service !== undefined){
const _errs12 = errors;
if(typeof data.service !== "string"){
validate25.errors = [{instancePath:instancePath+"/service",schemaPath:"#/properties/service/type",keyword:"type",params:{type: "string"},message:"must be string"}];
return false;
}
var valid0 = _errs12 === errors;
}
else {
var valid0 = true;
}
if(valid0){
if(data.version !== undefined){
let data6 = data.version;
const _errs14 = errors;
if(!(((typeof data6 == "number") && (!(data6 % 1) && !isNaN(data6))) && (isFinite(data6)))){
validate25.errors = [{instancePath:instancePath+"/version",schemaPath:"#/properties/version/type",keyword:"type",params:{type: "integer"},message:"must be integer"}];
return false;
}
if(errors === _errs14){
if((typeof data6 == "number") && (isFinite(data6))){
if(data6 > 65535 || isNaN(data6)){
validate25.errors = [{instancePath:instancePath+"/version",schemaPath:"#/properties/version/maximum",keyword:"maximum",params:{comparison: "<=", limit: 65535},message:"must be <= 65535"}];
return false;
}
else {
if(data6 < 0 || isNaN(data6)){
validate25.errors = [{instancePath:instancePath+"/version",schemaPath:"#/properties/version/minimum",keyword:"minimum",params:{comparison: ">=", limit: 0},message:"must be >= 0"}];
return false;
}
}
}
}
var valid0 = _errs14 === errors;
}
else {
var valid0 = true;
}
}
}
}
}
}
}
}
}
}
else {
validate25.errors = [{instancePath,schemaPath:"#/type",keyword:"type",params:{type: "object"},message:"must be object"}];
return false;
}
}
validate25.errors = vErrors;
return errors === 0;
}
validate25.evaluated = {"props":true,"dynamicProps":false,"dynamicItems":false};

export const validHandle = validate30;
const schema44 = {"$defs":{"DecimalU64":{"pattern":"^(0|[1-9][0-9]{0,18}|18446744073709551615|1[0-7][0-9]{18}|18[0-3][0-9]{17}|184[0-3][0-9]{16}|1844[0-5][0-9]{15}|18446[0-6][0-9]{14}|184467[0-3][0-9]{13}|1844674[0-3][0-9]{12}|184467440[0-6][0-9]{10}|1844674407[0-2][0-9]{9}|18446744073[0-6][0-9]{8}|1844674407370[0-8][0-9]{6}|18446744073709[0-4][0-9]{5}|184467440737095[0-4][0-9]{4}|1844674407370955[0-0][0-9]{3}|18446744073709551[0-5][0-9]{2}|184467440737095516[0-0][0-9]{1}|1844674407370955161[0-4][0-9]{0})$","type":"string"},"OperationId":{"maxLength":128,"minLength":16,"pattern":"^[A-Za-z0-9_-]+$","type":"string"},"OperationToken":{"additionalProperties":false,"properties":{"deadline":{"$ref":"#/$defs/DecimalU64"},"id":{"$ref":"#/$defs/OperationId"}},"required":["id","deadline"],"type":"object"}},"$schema":"https://json-schema.org/draft/2020-12/schema","additionalProperties":false,"description":"Safe to retain in browser storage: no arguments, result, credentials or passphrase.","properties":{"destination":{"type":"string"},"instance":{"type":"string"},"method":{"type":"string"},"operation":{"$ref":"#/$defs/OperationToken"},"service":{"type":"string"},"version":{"format":"uint16","maximum":65535,"minimum":0,"type":"integer"}},"required":["destination","instance","service","version","method","operation"],"title":"OperationHandle","type":"object"};
const schema45 = {"additionalProperties":false,"properties":{"deadline":{"$ref":"#/$defs/DecimalU64"},"id":{"$ref":"#/$defs/OperationId"}},"required":["id","deadline"],"type":"object"};
const schema46 = {"pattern":"^(0|[1-9][0-9]{0,18}|18446744073709551615|1[0-7][0-9]{18}|18[0-3][0-9]{17}|184[0-3][0-9]{16}|1844[0-5][0-9]{15}|18446[0-6][0-9]{14}|184467[0-3][0-9]{13}|1844674[0-3][0-9]{12}|184467440[0-6][0-9]{10}|1844674407[0-2][0-9]{9}|18446744073[0-6][0-9]{8}|1844674407370[0-8][0-9]{6}|18446744073709[0-4][0-9]{5}|184467440737095[0-4][0-9]{4}|1844674407370955[0-0][0-9]{3}|18446744073709551[0-5][0-9]{2}|184467440737095516[0-0][0-9]{1}|1844674407370955161[0-4][0-9]{0})$","type":"string"};
const schema47 = {"maxLength":128,"minLength":16,"pattern":"^[A-Za-z0-9_-]+$","type":"string"};

function validate31(data, {instancePath="", parentData, parentDataProperty, rootData=data, dynamicAnchors={}}={}){
let vErrors = null;
let errors = 0;
const evaluated0 = validate31.evaluated;
if(evaluated0.dynamicProps){
evaluated0.props = undefined;
}
if(evaluated0.dynamicItems){
evaluated0.items = undefined;
}
if(errors === 0){
if(data && typeof data == "object" && !Array.isArray(data)){
let missing0;
if(((data.id === undefined) && (missing0 = "id")) || ((data.deadline === undefined) && (missing0 = "deadline"))){
validate31.errors = [{instancePath,schemaPath:"#/required",keyword:"required",params:{missingProperty: missing0},message:"must have required property '"+missing0+"'"}];
return false;
}
else {
const _errs1 = errors;
for(const key0 in data){
if(!((key0 === "deadline") || (key0 === "id"))){
validate31.errors = [{instancePath,schemaPath:"#/additionalProperties",keyword:"additionalProperties",params:{additionalProperty: key0},message:"must NOT have additional properties"}];
return false;
break;
}
}
if(_errs1 === errors){
if(data.deadline !== undefined){
let data0 = data.deadline;
const _errs2 = errors;
const _errs3 = errors;
if(errors === _errs3){
if(typeof data0 === "string"){
if(!pattern5.test(data0)){
validate31.errors = [{instancePath:instancePath+"/deadline",schemaPath:"#/$defs/DecimalU64/pattern",keyword:"pattern",params:{pattern: "^(0|[1-9][0-9]{0,18}|18446744073709551615|1[0-7][0-9]{18}|18[0-3][0-9]{17}|184[0-3][0-9]{16}|1844[0-5][0-9]{15}|18446[0-6][0-9]{14}|184467[0-3][0-9]{13}|1844674[0-3][0-9]{12}|184467440[0-6][0-9]{10}|1844674407[0-2][0-9]{9}|18446744073[0-6][0-9]{8}|1844674407370[0-8][0-9]{6}|18446744073709[0-4][0-9]{5}|184467440737095[0-4][0-9]{4}|1844674407370955[0-0][0-9]{3}|18446744073709551[0-5][0-9]{2}|184467440737095516[0-0][0-9]{1}|1844674407370955161[0-4][0-9]{0})$"},message:"must match pattern \""+"^(0|[1-9][0-9]{0,18}|18446744073709551615|1[0-7][0-9]{18}|18[0-3][0-9]{17}|184[0-3][0-9]{16}|1844[0-5][0-9]{15}|18446[0-6][0-9]{14}|184467[0-3][0-9]{13}|1844674[0-3][0-9]{12}|184467440[0-6][0-9]{10}|1844674407[0-2][0-9]{9}|18446744073[0-6][0-9]{8}|1844674407370[0-8][0-9]{6}|18446744073709[0-4][0-9]{5}|184467440737095[0-4][0-9]{4}|1844674407370955[0-0][0-9]{3}|18446744073709551[0-5][0-9]{2}|184467440737095516[0-0][0-9]{1}|1844674407370955161[0-4][0-9]{0})$"+"\""}];
return false;
}
}
else {
validate31.errors = [{instancePath:instancePath+"/deadline",schemaPath:"#/$defs/DecimalU64/type",keyword:"type",params:{type: "string"},message:"must be string"}];
return false;
}
}
var valid0 = _errs2 === errors;
}
else {
var valid0 = true;
}
if(valid0){
if(data.id !== undefined){
let data1 = data.id;
const _errs5 = errors;
const _errs6 = errors;
if(errors === _errs6){
if(typeof data1 === "string"){
if(func1(data1) > 128){
validate31.errors = [{instancePath:instancePath+"/id",schemaPath:"#/$defs/OperationId/maxLength",keyword:"maxLength",params:{limit: 128},message:"must NOT have more than 128 characters"}];
return false;
}
else {
if(func1(data1) < 16){
validate31.errors = [{instancePath:instancePath+"/id",schemaPath:"#/$defs/OperationId/minLength",keyword:"minLength",params:{limit: 16},message:"must NOT have fewer than 16 characters"}];
return false;
}
else {
if(!pattern4.test(data1)){
validate31.errors = [{instancePath:instancePath+"/id",schemaPath:"#/$defs/OperationId/pattern",keyword:"pattern",params:{pattern: "^[A-Za-z0-9_-]+$"},message:"must match pattern \""+"^[A-Za-z0-9_-]+$"+"\""}];
return false;
}
}
}
}
else {
validate31.errors = [{instancePath:instancePath+"/id",schemaPath:"#/$defs/OperationId/type",keyword:"type",params:{type: "string"},message:"must be string"}];
return false;
}
}
var valid0 = _errs5 === errors;
}
else {
var valid0 = true;
}
}
}
}
}
else {
validate31.errors = [{instancePath,schemaPath:"#/type",keyword:"type",params:{type: "object"},message:"must be object"}];
return false;
}
}
validate31.errors = vErrors;
return errors === 0;
}
validate31.evaluated = {"props":true,"dynamicProps":false,"dynamicItems":false};


function validate30(data, {instancePath="", parentData, parentDataProperty, rootData=data, dynamicAnchors={}}={}){
let vErrors = null;
let errors = 0;
const evaluated0 = validate30.evaluated;
if(evaluated0.dynamicProps){
evaluated0.props = undefined;
}
if(evaluated0.dynamicItems){
evaluated0.items = undefined;
}
if(errors === 0){
if(data && typeof data == "object" && !Array.isArray(data)){
let missing0;
if(((((((data.destination === undefined) && (missing0 = "destination")) || ((data.instance === undefined) && (missing0 = "instance"))) || ((data.service === undefined) && (missing0 = "service"))) || ((data.version === undefined) && (missing0 = "version"))) || ((data.method === undefined) && (missing0 = "method"))) || ((data.operation === undefined) && (missing0 = "operation"))){
validate30.errors = [{instancePath,schemaPath:"#/required",keyword:"required",params:{missingProperty: missing0},message:"must have required property '"+missing0+"'"}];
return false;
}
else {
const _errs1 = errors;
for(const key0 in data){
if(!((((((key0 === "destination") || (key0 === "instance")) || (key0 === "method")) || (key0 === "operation")) || (key0 === "service")) || (key0 === "version"))){
validate30.errors = [{instancePath,schemaPath:"#/additionalProperties",keyword:"additionalProperties",params:{additionalProperty: key0},message:"must NOT have additional properties"}];
return false;
break;
}
}
if(_errs1 === errors){
if(data.destination !== undefined){
const _errs2 = errors;
if(typeof data.destination !== "string"){
validate30.errors = [{instancePath:instancePath+"/destination",schemaPath:"#/properties/destination/type",keyword:"type",params:{type: "string"},message:"must be string"}];
return false;
}
var valid0 = _errs2 === errors;
}
else {
var valid0 = true;
}
if(valid0){
if(data.instance !== undefined){
const _errs4 = errors;
if(typeof data.instance !== "string"){
validate30.errors = [{instancePath:instancePath+"/instance",schemaPath:"#/properties/instance/type",keyword:"type",params:{type: "string"},message:"must be string"}];
return false;
}
var valid0 = _errs4 === errors;
}
else {
var valid0 = true;
}
if(valid0){
if(data.method !== undefined){
const _errs6 = errors;
if(typeof data.method !== "string"){
validate30.errors = [{instancePath:instancePath+"/method",schemaPath:"#/properties/method/type",keyword:"type",params:{type: "string"},message:"must be string"}];
return false;
}
var valid0 = _errs6 === errors;
}
else {
var valid0 = true;
}
if(valid0){
if(data.operation !== undefined){
const _errs8 = errors;
if(!(validate31(data.operation, {instancePath:instancePath+"/operation",parentData:data,parentDataProperty:"operation",rootData,dynamicAnchors}))){
vErrors = vErrors === null ? validate31.errors : vErrors.concat(validate31.errors);
errors = vErrors.length;
}
var valid0 = _errs8 === errors;
}
else {
var valid0 = true;
}
if(valid0){
if(data.service !== undefined){
const _errs9 = errors;
if(typeof data.service !== "string"){
validate30.errors = [{instancePath:instancePath+"/service",schemaPath:"#/properties/service/type",keyword:"type",params:{type: "string"},message:"must be string"}];
return false;
}
var valid0 = _errs9 === errors;
}
else {
var valid0 = true;
}
if(valid0){
if(data.version !== undefined){
let data5 = data.version;
const _errs11 = errors;
if(!(((typeof data5 == "number") && (!(data5 % 1) && !isNaN(data5))) && (isFinite(data5)))){
validate30.errors = [{instancePath:instancePath+"/version",schemaPath:"#/properties/version/type",keyword:"type",params:{type: "integer"},message:"must be integer"}];
return false;
}
if(errors === _errs11){
if((typeof data5 == "number") && (isFinite(data5))){
if(data5 > 65535 || isNaN(data5)){
validate30.errors = [{instancePath:instancePath+"/version",schemaPath:"#/properties/version/maximum",keyword:"maximum",params:{comparison: "<=", limit: 65535},message:"must be <= 65535"}];
return false;
}
else {
if(data5 < 0 || isNaN(data5)){
validate30.errors = [{instancePath:instancePath+"/version",schemaPath:"#/properties/version/minimum",keyword:"minimum",params:{comparison: ">=", limit: 0},message:"must be >= 0"}];
return false;
}
}
}
}
var valid0 = _errs11 === errors;
}
else {
var valid0 = true;
}
}
}
}
}
}
}
}
}
else {
validate30.errors = [{instancePath,schemaPath:"#/type",keyword:"type",params:{type: "object"},message:"must be object"}];
return false;
}
}
validate30.errors = vErrors;
return errors === 0;
}
validate30.evaluated = {"props":true,"dynamicProps":false,"dynamicItems":false};
