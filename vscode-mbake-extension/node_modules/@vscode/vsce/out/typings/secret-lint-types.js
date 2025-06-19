"use strict";
// To parse this data:
//
//   import { Convert, SecretLintOutput } from "./file";
//
//   const secretLintOutput = Convert.toSecretLintOutput(json);
//
// These functions will throw an error if the JSON doesn't
// match the expected interface, even if the JSON is valid.
Object.defineProperty(exports, "__esModule", { value: true });
exports.Convert = exports.ColumnKind = exports.Version = exports.Status = exports.SuppressionKind = exports.ResultKind = exports.Importance = exports.BaselineState = exports.Content = exports.Level = exports.Role = void 0;
var Role;
(function (Role) {
    Role["Added"] = "added";
    Role["AnalysisTarget"] = "analysisTarget";
    Role["Attachment"] = "attachment";
    Role["DebugOutputFile"] = "debugOutputFile";
    Role["Deleted"] = "deleted";
    Role["Directory"] = "directory";
    Role["Driver"] = "driver";
    Role["Extension"] = "extension";
    Role["MemoryContents"] = "memoryContents";
    Role["Modified"] = "modified";
    Role["Policy"] = "policy";
    Role["ReferencedOnCommandLine"] = "referencedOnCommandLine";
    Role["Renamed"] = "renamed";
    Role["ResponseFile"] = "responseFile";
    Role["ResultFile"] = "resultFile";
    Role["StandardStream"] = "standardStream";
    Role["Taxonomy"] = "taxonomy";
    Role["ToolSpecifiedConfiguration"] = "toolSpecifiedConfiguration";
    Role["TracedFile"] = "tracedFile";
    Role["Translation"] = "translation";
    Role["Uncontrolled"] = "uncontrolled";
    Role["Unmodified"] = "unmodified";
    Role["UserSpecifiedConfiguration"] = "userSpecifiedConfiguration";
})(Role = exports.Role || (exports.Role = {}));
/**
 * Specifies the failure level for the report.
 *
 * A value specifying the severity level of the notification.
 *
 * A value specifying the severity level of the result.
 */
var Level;
(function (Level) {
    Level["Error"] = "error";
    Level["None"] = "none";
    Level["Note"] = "note";
    Level["Warning"] = "warning";
})(Level = exports.Level || (exports.Level = {}));
var Content;
(function (Content) {
    Content["LocalizedData"] = "localizedData";
    Content["NonLocalizedData"] = "nonLocalizedData";
})(Content = exports.Content || (exports.Content = {}));
/**
 * The state of a result relative to a baseline of a previous run.
 */
var BaselineState;
(function (BaselineState) {
    BaselineState["Absent"] = "absent";
    BaselineState["New"] = "new";
    BaselineState["Unchanged"] = "unchanged";
    BaselineState["Updated"] = "updated";
})(BaselineState = exports.BaselineState || (exports.BaselineState = {}));
/**
 * Specifies the importance of this location in understanding the code flow in which it
 * occurs. The order from most to least important is "essential", "important",
 * "unimportant". Default: "important".
 */
var Importance;
(function (Importance) {
    Importance["Essential"] = "essential";
    Importance["Important"] = "important";
    Importance["Unimportant"] = "unimportant";
})(Importance = exports.Importance || (exports.Importance = {}));
/**
 * A value that categorizes results by evaluation state.
 */
var ResultKind;
(function (ResultKind) {
    ResultKind["Fail"] = "fail";
    ResultKind["Informational"] = "informational";
    ResultKind["NotApplicable"] = "notApplicable";
    ResultKind["Open"] = "open";
    ResultKind["Pass"] = "pass";
    ResultKind["Review"] = "review";
})(ResultKind = exports.ResultKind || (exports.ResultKind = {}));
/**
 * A string that indicates where the suppression is persisted.
 */
var SuppressionKind;
(function (SuppressionKind) {
    SuppressionKind["External"] = "external";
    SuppressionKind["InSource"] = "inSource";
})(SuppressionKind = exports.SuppressionKind || (exports.SuppressionKind = {}));
/**
 * A string that indicates the review status of the suppression.
 */
var Status;
(function (Status) {
    Status["Accepted"] = "accepted";
    Status["Rejected"] = "rejected";
    Status["UnderReview"] = "underReview";
})(Status = exports.Status || (exports.Status = {}));
/**
 * The SARIF format version of this external properties object.
 *
 * The SARIF format version of this log file.
 */
var Version;
(function (Version) {
    Version["The210"] = "2.1.0";
})(Version = exports.Version || (exports.Version = {}));
/**
 * Specifies the unit in which the tool measures columns.
 */
var ColumnKind;
(function (ColumnKind) {
    ColumnKind["UnicodeCodePoints"] = "unicodeCodePoints";
    ColumnKind["Utf16CodeUnits"] = "utf16CodeUnits";
})(ColumnKind = exports.ColumnKind || (exports.ColumnKind = {}));
// Converts JSON strings to/from your types
// and asserts the results of JSON.parse at runtime
class Convert {
    static toSecretLintOutput(json) {
        return cast(JSON.parse(json), r("SecretLintOutput"));
    }
    static SecretLintOutputToJson(value) {
        return JSON.stringify(uncast(value, r("SecretLintOutput")), null, 2);
    }
}
exports.Convert = Convert;
function invalidValue(typ, val, key, parent = '') {
    const prettyTyp = prettyTypeName(typ);
    const parentText = parent ? ` on ${parent}` : '';
    const keyText = key ? ` for key "${key}"` : '';
    throw Error(`Invalid value${keyText}${parentText}. Expected ${prettyTyp} but got ${JSON.stringify(val)}`);
}
function prettyTypeName(typ) {
    if (Array.isArray(typ)) {
        if (typ.length === 2 && typ[0] === undefined) {
            return `an optional ${prettyTypeName(typ[1])}`;
        }
        else {
            return `one of [${typ.map(a => { return prettyTypeName(a); }).join(", ")}]`;
        }
    }
    else if (typeof typ === "object" && typ.literal !== undefined) {
        return typ.literal;
    }
    else {
        return typeof typ;
    }
}
function jsonToJSProps(typ) {
    if (typ.jsonToJS === undefined) {
        const map = {};
        typ.props.forEach((p) => map[p.json] = { key: p.js, typ: p.typ });
        typ.jsonToJS = map;
    }
    return typ.jsonToJS;
}
function jsToJSONProps(typ) {
    if (typ.jsToJSON === undefined) {
        const map = {};
        typ.props.forEach((p) => map[p.js] = { key: p.json, typ: p.typ });
        typ.jsToJSON = map;
    }
    return typ.jsToJSON;
}
function transform(val, typ, getProps, key = '', parent = '') {
    function transformPrimitive(typ, val) {
        if (typeof typ === typeof val)
            return val;
        return invalidValue(typ, val, key, parent);
    }
    function transformUnion(typs, val) {
        // val must validate against one typ in typs
        const l = typs.length;
        for (let i = 0; i < l; i++) {
            const typ = typs[i];
            try {
                return transform(val, typ, getProps);
            }
            catch (_) { }
        }
        return invalidValue(typs, val, key, parent);
    }
    function transformEnum(cases, val) {
        if (cases.indexOf(val) !== -1)
            return val;
        return invalidValue(cases.map(a => { return l(a); }), val, key, parent);
    }
    function transformArray(typ, val) {
        // val must be an array with no invalid elements
        if (!Array.isArray(val))
            return invalidValue(l("array"), val, key, parent);
        return val.map(el => transform(el, typ, getProps));
    }
    function transformDate(val) {
        if (val === null) {
            return null;
        }
        const d = new Date(val);
        if (isNaN(d.valueOf())) {
            return invalidValue(l("Date"), val, key, parent);
        }
        return d;
    }
    function transformObject(props, additional, val) {
        if (val === null || typeof val !== "object" || Array.isArray(val)) {
            return invalidValue(l(ref || "object"), val, key, parent);
        }
        const result = {};
        Object.getOwnPropertyNames(props).forEach(key => {
            const prop = props[key];
            const v = Object.prototype.hasOwnProperty.call(val, key) ? val[key] : undefined;
            result[prop.key] = transform(v, prop.typ, getProps, key, ref);
        });
        Object.getOwnPropertyNames(val).forEach(key => {
            if (!Object.prototype.hasOwnProperty.call(props, key)) {
                result[key] = transform(val[key], additional, getProps, key, ref);
            }
        });
        return result;
    }
    if (typ === "any")
        return val;
    if (typ === null) {
        if (val === null)
            return val;
        return invalidValue(typ, val, key, parent);
    }
    if (typ === false)
        return invalidValue(typ, val, key, parent);
    let ref = undefined;
    while (typeof typ === "object" && typ.ref !== undefined) {
        ref = typ.ref;
        typ = typeMap[typ.ref];
    }
    if (Array.isArray(typ))
        return transformEnum(typ, val);
    if (typeof typ === "object") {
        return typ.hasOwnProperty("unionMembers") ? transformUnion(typ.unionMembers, val)
            : typ.hasOwnProperty("arrayItems") ? transformArray(typ.arrayItems, val)
                : typ.hasOwnProperty("props") ? transformObject(getProps(typ), typ.additional, val)
                    : invalidValue(typ, val, key, parent);
    }
    // Numbers can be parsed by Date but shouldn't be.
    if (typ === Date && typeof val !== "number")
        return transformDate(val);
    return transformPrimitive(typ, val);
}
function cast(val, typ) {
    return transform(val, typ, jsonToJSProps);
}
function uncast(val, typ) {
    return transform(val, typ, jsToJSONProps);
}
function l(typ) {
    return { literal: typ };
}
function a(typ) {
    return { arrayItems: typ };
}
function u(...typs) {
    return { unionMembers: typs };
}
function o(props, additional) {
    return { props, additional };
}
function m(additional) {
    return { props: [], additional };
}
function r(name) {
    return { ref: name };
}
const typeMap = {
    "SecretLintOutput": o([
        { json: "$schema", js: "$schema", typ: u(undefined, "") },
        { json: "inlineExternalProperties", js: "inlineExternalProperties", typ: u(undefined, a(r("ExternalProperties"))) },
        { json: "properties", js: "properties", typ: u(undefined, r("PropertyBag")) },
        { json: "runs", js: "runs", typ: a(r("Run")) },
        { json: "version", js: "version", typ: r("Version") },
    ], false),
    "ExternalProperties": o([
        { json: "addresses", js: "addresses", typ: u(undefined, a(r("Address"))) },
        { json: "artifacts", js: "artifacts", typ: u(undefined, a(r("Artifact"))) },
        { json: "conversion", js: "conversion", typ: u(undefined, r("Conversion")) },
        { json: "driver", js: "driver", typ: u(undefined, r("ToolComponent")) },
        { json: "extensions", js: "extensions", typ: u(undefined, a(r("ToolComponent"))) },
        { json: "externalizedProperties", js: "externalizedProperties", typ: u(undefined, r("PropertyBag")) },
        { json: "graphs", js: "graphs", typ: u(undefined, a(r("Graph"))) },
        { json: "guid", js: "guid", typ: u(undefined, "") },
        { json: "invocations", js: "invocations", typ: u(undefined, a(r("Invocation"))) },
        { json: "logicalLocations", js: "logicalLocations", typ: u(undefined, a(r("LogicalLocation"))) },
        { json: "policies", js: "policies", typ: u(undefined, a(r("ToolComponent"))) },
        { json: "properties", js: "properties", typ: u(undefined, r("PropertyBag")) },
        { json: "results", js: "results", typ: u(undefined, a(r("Result"))) },
        { json: "runGuid", js: "runGuid", typ: u(undefined, "") },
        { json: "schema", js: "schema", typ: u(undefined, "") },
        { json: "taxonomies", js: "taxonomies", typ: u(undefined, a(r("ToolComponent"))) },
        { json: "threadFlowLocations", js: "threadFlowLocations", typ: u(undefined, a(r("ThreadFlowLocation"))) },
        { json: "translations", js: "translations", typ: u(undefined, a(r("ToolComponent"))) },
        { json: "version", js: "version", typ: u(undefined, r("Version")) },
        { json: "webRequests", js: "webRequests", typ: u(undefined, a(r("WebRequest"))) },
        { json: "webResponses", js: "webResponses", typ: u(undefined, a(r("WebResponse"))) },
    ], false),
    "Address": o([
        { json: "absoluteAddress", js: "absoluteAddress", typ: u(undefined, 0) },
        { json: "fullyQualifiedName", js: "fullyQualifiedName", typ: u(undefined, "") },
        { json: "index", js: "index", typ: u(undefined, 0) },
        { json: "kind", js: "kind", typ: u(undefined, "") },
        { json: "length", js: "length", typ: u(undefined, 0) },
        { json: "name", js: "name", typ: u(undefined, "") },
        { json: "offsetFromParent", js: "offsetFromParent", typ: u(undefined, 0) },
        { json: "parentIndex", js: "parentIndex", typ: u(undefined, 0) },
        { json: "properties", js: "properties", typ: u(undefined, r("PropertyBag")) },
        { json: "relativeAddress", js: "relativeAddress", typ: u(undefined, 0) },
    ], false),
    "PropertyBag": o([
        { json: "tags", js: "tags", typ: u(undefined, a("")) },
    ], "any"),
    "Artifact": o([
        { json: "contents", js: "contents", typ: u(undefined, r("ArtifactContent")) },
        { json: "description", js: "description", typ: u(undefined, r("Message")) },
        { json: "encoding", js: "encoding", typ: u(undefined, "") },
        { json: "hashes", js: "hashes", typ: u(undefined, m("")) },
        { json: "lastModifiedTimeUtc", js: "lastModifiedTimeUtc", typ: u(undefined, Date) },
        { json: "length", js: "length", typ: u(undefined, 0) },
        { json: "location", js: "location", typ: u(undefined, r("ArtifactLocation")) },
        { json: "mimeType", js: "mimeType", typ: u(undefined, "") },
        { json: "offset", js: "offset", typ: u(undefined, 0) },
        { json: "parentIndex", js: "parentIndex", typ: u(undefined, 0) },
        { json: "properties", js: "properties", typ: u(undefined, r("PropertyBag")) },
        { json: "roles", js: "roles", typ: u(undefined, a(r("Role"))) },
        { json: "sourceLanguage", js: "sourceLanguage", typ: u(undefined, "") },
    ], false),
    "ArtifactContent": o([
        { json: "binary", js: "binary", typ: u(undefined, "") },
        { json: "properties", js: "properties", typ: u(undefined, r("PropertyBag")) },
        { json: "rendered", js: "rendered", typ: u(undefined, r("MultiformatMessageString")) },
        { json: "text", js: "text", typ: u(undefined, "") },
    ], false),
    "MultiformatMessageString": o([
        { json: "markdown", js: "markdown", typ: u(undefined, "") },
        { json: "properties", js: "properties", typ: u(undefined, r("PropertyBag")) },
        { json: "text", js: "text", typ: "" },
    ], false),
    "Message": o([
        { json: "arguments", js: "arguments", typ: u(undefined, a("")) },
        { json: "id", js: "id", typ: u(undefined, "") },
        { json: "markdown", js: "markdown", typ: u(undefined, "") },
        { json: "properties", js: "properties", typ: u(undefined, r("PropertyBag")) },
        { json: "text", js: "text", typ: u(undefined, "") },
    ], false),
    "ArtifactLocation": o([
        { json: "description", js: "description", typ: u(undefined, r("Message")) },
        { json: "index", js: "index", typ: u(undefined, 0) },
        { json: "properties", js: "properties", typ: u(undefined, r("PropertyBag")) },
        { json: "uri", js: "uri", typ: u(undefined, "") },
        { json: "uriBaseId", js: "uriBaseId", typ: u(undefined, "") },
    ], false),
    "Conversion": o([
        { json: "analysisToolLogFiles", js: "analysisToolLogFiles", typ: u(undefined, a(r("ArtifactLocation"))) },
        { json: "invocation", js: "invocation", typ: u(undefined, r("Invocation")) },
        { json: "properties", js: "properties", typ: u(undefined, r("PropertyBag")) },
        { json: "tool", js: "tool", typ: r("Tool") },
    ], false),
    "Invocation": o([
        { json: "account", js: "account", typ: u(undefined, "") },
        { json: "arguments", js: "arguments", typ: u(undefined, a("")) },
        { json: "commandLine", js: "commandLine", typ: u(undefined, "") },
        { json: "endTimeUtc", js: "endTimeUtc", typ: u(undefined, Date) },
        { json: "environmentVariables", js: "environmentVariables", typ: u(undefined, m("")) },
        { json: "executableLocation", js: "executableLocation", typ: u(undefined, r("ArtifactLocation")) },
        { json: "executionSuccessful", js: "executionSuccessful", typ: true },
        { json: "exitCode", js: "exitCode", typ: u(undefined, 0) },
        { json: "exitCodeDescription", js: "exitCodeDescription", typ: u(undefined, "") },
        { json: "exitSignalName", js: "exitSignalName", typ: u(undefined, "") },
        { json: "exitSignalNumber", js: "exitSignalNumber", typ: u(undefined, 0) },
        { json: "machine", js: "machine", typ: u(undefined, "") },
        { json: "notificationConfigurationOverrides", js: "notificationConfigurationOverrides", typ: u(undefined, a(r("ConfigurationOverride"))) },
        { json: "processId", js: "processId", typ: u(undefined, 0) },
        { json: "processStartFailureMessage", js: "processStartFailureMessage", typ: u(undefined, "") },
        { json: "properties", js: "properties", typ: u(undefined, r("PropertyBag")) },
        { json: "responseFiles", js: "responseFiles", typ: u(undefined, a(r("ArtifactLocation"))) },
        { json: "ruleConfigurationOverrides", js: "ruleConfigurationOverrides", typ: u(undefined, a(r("ConfigurationOverride"))) },
        { json: "startTimeUtc", js: "startTimeUtc", typ: u(undefined, Date) },
        { json: "stderr", js: "stderr", typ: u(undefined, r("ArtifactLocation")) },
        { json: "stdin", js: "stdin", typ: u(undefined, r("ArtifactLocation")) },
        { json: "stdout", js: "stdout", typ: u(undefined, r("ArtifactLocation")) },
        { json: "stdoutStderr", js: "stdoutStderr", typ: u(undefined, r("ArtifactLocation")) },
        { json: "toolConfigurationNotifications", js: "toolConfigurationNotifications", typ: u(undefined, a(r("Notification"))) },
        { json: "toolExecutionNotifications", js: "toolExecutionNotifications", typ: u(undefined, a(r("Notification"))) },
        { json: "workingDirectory", js: "workingDirectory", typ: u(undefined, r("ArtifactLocation")) },
    ], false),
    "ConfigurationOverride": o([
        { json: "configuration", js: "configuration", typ: r("ReportingConfiguration") },
        { json: "descriptor", js: "descriptor", typ: r("ReportingDescriptorReference") },
        { json: "properties", js: "properties", typ: u(undefined, r("PropertyBag")) },
    ], false),
    "ReportingConfiguration": o([
        { json: "enabled", js: "enabled", typ: u(undefined, true) },
        { json: "level", js: "level", typ: u(undefined, r("Level")) },
        { json: "parameters", js: "parameters", typ: u(undefined, r("PropertyBag")) },
        { json: "properties", js: "properties", typ: u(undefined, r("PropertyBag")) },
        { json: "rank", js: "rank", typ: u(undefined, 3.14) },
    ], false),
    "ReportingDescriptorReference": o([
        { json: "guid", js: "guid", typ: u(undefined, "") },
        { json: "id", js: "id", typ: u(undefined, "") },
        { json: "index", js: "index", typ: u(undefined, 0) },
        { json: "properties", js: "properties", typ: u(undefined, r("PropertyBag")) },
        { json: "toolComponent", js: "toolComponent", typ: u(undefined, r("ToolComponentReference")) },
    ], false),
    "ToolComponentReference": o([
        { json: "guid", js: "guid", typ: u(undefined, "") },
        { json: "index", js: "index", typ: u(undefined, 0) },
        { json: "name", js: "name", typ: u(undefined, "") },
        { json: "properties", js: "properties", typ: u(undefined, r("PropertyBag")) },
    ], false),
    "Notification": o([
        { json: "associatedRule", js: "associatedRule", typ: u(undefined, r("ReportingDescriptorReference")) },
        { json: "descriptor", js: "descriptor", typ: u(undefined, r("ReportingDescriptorReference")) },
        { json: "exception", js: "exception", typ: u(undefined, r("Exception")) },
        { json: "level", js: "level", typ: u(undefined, r("Level")) },
        { json: "locations", js: "locations", typ: u(undefined, a(r("Location"))) },
        { json: "message", js: "message", typ: r("Message") },
        { json: "properties", js: "properties", typ: u(undefined, r("PropertyBag")) },
        { json: "threadId", js: "threadId", typ: u(undefined, 0) },
        { json: "timeUtc", js: "timeUtc", typ: u(undefined, Date) },
    ], false),
    "Exception": o([
        { json: "innerExceptions", js: "innerExceptions", typ: u(undefined, a(r("Exception"))) },
        { json: "kind", js: "kind", typ: u(undefined, "") },
        { json: "message", js: "message", typ: u(undefined, "") },
        { json: "properties", js: "properties", typ: u(undefined, r("PropertyBag")) },
        { json: "stack", js: "stack", typ: u(undefined, r("Stack")) },
    ], false),
    "Stack": o([
        { json: "frames", js: "frames", typ: a(r("StackFrame")) },
        { json: "message", js: "message", typ: u(undefined, r("Message")) },
        { json: "properties", js: "properties", typ: u(undefined, r("PropertyBag")) },
    ], false),
    "StackFrame": o([
        { json: "location", js: "location", typ: u(undefined, r("Location")) },
        { json: "module", js: "module", typ: u(undefined, "") },
        { json: "parameters", js: "parameters", typ: u(undefined, a("")) },
        { json: "properties", js: "properties", typ: u(undefined, r("PropertyBag")) },
        { json: "threadId", js: "threadId", typ: u(undefined, 0) },
    ], false),
    "Location": o([
        { json: "annotations", js: "annotations", typ: u(undefined, a(r("Region"))) },
        { json: "id", js: "id", typ: u(undefined, 0) },
        { json: "logicalLocations", js: "logicalLocations", typ: u(undefined, a(r("LogicalLocation"))) },
        { json: "message", js: "message", typ: u(undefined, r("Message")) },
        { json: "physicalLocation", js: "physicalLocation", typ: u(undefined, r("PhysicalLocation")) },
        { json: "properties", js: "properties", typ: u(undefined, r("PropertyBag")) },
        { json: "relationships", js: "relationships", typ: u(undefined, a(r("LocationRelationship"))) },
    ], false),
    "Region": o([
        { json: "byteLength", js: "byteLength", typ: u(undefined, 0) },
        { json: "byteOffset", js: "byteOffset", typ: u(undefined, 0) },
        { json: "charLength", js: "charLength", typ: u(undefined, 0) },
        { json: "charOffset", js: "charOffset", typ: u(undefined, 0) },
        { json: "endColumn", js: "endColumn", typ: u(undefined, 0) },
        { json: "endLine", js: "endLine", typ: u(undefined, 0) },
        { json: "message", js: "message", typ: u(undefined, r("Message")) },
        { json: "properties", js: "properties", typ: u(undefined, r("PropertyBag")) },
        { json: "snippet", js: "snippet", typ: u(undefined, r("ArtifactContent")) },
        { json: "sourceLanguage", js: "sourceLanguage", typ: u(undefined, "") },
        { json: "startColumn", js: "startColumn", typ: u(undefined, 0) },
        { json: "startLine", js: "startLine", typ: u(undefined, 0) },
    ], false),
    "LogicalLocation": o([
        { json: "decoratedName", js: "decoratedName", typ: u(undefined, "") },
        { json: "fullyQualifiedName", js: "fullyQualifiedName", typ: u(undefined, "") },
        { json: "index", js: "index", typ: u(undefined, 0) },
        { json: "kind", js: "kind", typ: u(undefined, "") },
        { json: "name", js: "name", typ: u(undefined, "") },
        { json: "parentIndex", js: "parentIndex", typ: u(undefined, 0) },
        { json: "properties", js: "properties", typ: u(undefined, r("PropertyBag")) },
    ], false),
    "PhysicalLocation": o([
        { json: "address", js: "address", typ: u(undefined, r("Address")) },
        { json: "artifactLocation", js: "artifactLocation", typ: u(undefined, r("ArtifactLocation")) },
        { json: "contextRegion", js: "contextRegion", typ: u(undefined, r("Region")) },
        { json: "properties", js: "properties", typ: u(undefined, r("PropertyBag")) },
        { json: "region", js: "region", typ: u(undefined, r("Region")) },
    ], false),
    "LocationRelationship": o([
        { json: "description", js: "description", typ: u(undefined, r("Message")) },
        { json: "kinds", js: "kinds", typ: u(undefined, a("")) },
        { json: "properties", js: "properties", typ: u(undefined, r("PropertyBag")) },
        { json: "target", js: "target", typ: 0 },
    ], false),
    "Tool": o([
        { json: "driver", js: "driver", typ: r("ToolComponent") },
        { json: "extensions", js: "extensions", typ: u(undefined, a(r("ToolComponent"))) },
        { json: "properties", js: "properties", typ: u(undefined, r("PropertyBag")) },
    ], false),
    "ToolComponent": o([
        { json: "associatedComponent", js: "associatedComponent", typ: u(undefined, r("ToolComponentReference")) },
        { json: "contents", js: "contents", typ: u(undefined, a(r("Content"))) },
        { json: "dottedQuadFileVersion", js: "dottedQuadFileVersion", typ: u(undefined, "") },
        { json: "downloadUri", js: "downloadUri", typ: u(undefined, "") },
        { json: "fullDescription", js: "fullDescription", typ: u(undefined, r("MultiformatMessageString")) },
        { json: "fullName", js: "fullName", typ: u(undefined, "") },
        { json: "globalMessageStrings", js: "globalMessageStrings", typ: u(undefined, m(r("MultiformatMessageString"))) },
        { json: "guid", js: "guid", typ: u(undefined, "") },
        { json: "informationUri", js: "informationUri", typ: u(undefined, "") },
        { json: "isComprehensive", js: "isComprehensive", typ: u(undefined, true) },
        { json: "language", js: "language", typ: u(undefined, "") },
        { json: "localizedDataSemanticVersion", js: "localizedDataSemanticVersion", typ: u(undefined, "") },
        { json: "locations", js: "locations", typ: u(undefined, a(r("ArtifactLocation"))) },
        { json: "minimumRequiredLocalizedDataSemanticVersion", js: "minimumRequiredLocalizedDataSemanticVersion", typ: u(undefined, "") },
        { json: "name", js: "name", typ: "" },
        { json: "notifications", js: "notifications", typ: u(undefined, a(r("ReportingDescriptor"))) },
        { json: "organization", js: "organization", typ: u(undefined, "") },
        { json: "product", js: "product", typ: u(undefined, "") },
        { json: "productSuite", js: "productSuite", typ: u(undefined, "") },
        { json: "properties", js: "properties", typ: u(undefined, r("PropertyBag")) },
        { json: "releaseDateUtc", js: "releaseDateUtc", typ: u(undefined, "") },
        { json: "rules", js: "rules", typ: u(undefined, a(r("ReportingDescriptor"))) },
        { json: "semanticVersion", js: "semanticVersion", typ: u(undefined, "") },
        { json: "shortDescription", js: "shortDescription", typ: u(undefined, r("MultiformatMessageString")) },
        { json: "supportedTaxonomies", js: "supportedTaxonomies", typ: u(undefined, a(r("ToolComponentReference"))) },
        { json: "taxa", js: "taxa", typ: u(undefined, a(r("ReportingDescriptor"))) },
        { json: "translationMetadata", js: "translationMetadata", typ: u(undefined, r("TranslationMetadata")) },
        { json: "version", js: "version", typ: u(undefined, "") },
    ], false),
    "ReportingDescriptor": o([
        { json: "defaultConfiguration", js: "defaultConfiguration", typ: u(undefined, r("ReportingConfiguration")) },
        { json: "deprecatedGuids", js: "deprecatedGuids", typ: u(undefined, a("")) },
        { json: "deprecatedIds", js: "deprecatedIds", typ: u(undefined, a("")) },
        { json: "deprecatedNames", js: "deprecatedNames", typ: u(undefined, a("")) },
        { json: "fullDescription", js: "fullDescription", typ: u(undefined, r("MultiformatMessageString")) },
        { json: "guid", js: "guid", typ: u(undefined, "") },
        { json: "help", js: "help", typ: u(undefined, r("MultiformatMessageString")) },
        { json: "helpUri", js: "helpUri", typ: u(undefined, "") },
        { json: "id", js: "id", typ: "" },
        { json: "messageStrings", js: "messageStrings", typ: u(undefined, m(r("MultiformatMessageString"))) },
        { json: "name", js: "name", typ: u(undefined, "") },
        { json: "properties", js: "properties", typ: u(undefined, r("PropertyBag")) },
        { json: "relationships", js: "relationships", typ: u(undefined, a(r("ReportingDescriptorRelationship"))) },
        { json: "shortDescription", js: "shortDescription", typ: u(undefined, r("MultiformatMessageString")) },
    ], false),
    "ReportingDescriptorRelationship": o([
        { json: "description", js: "description", typ: u(undefined, r("Message")) },
        { json: "kinds", js: "kinds", typ: u(undefined, a("")) },
        { json: "properties", js: "properties", typ: u(undefined, r("PropertyBag")) },
        { json: "target", js: "target", typ: r("ReportingDescriptorReference") },
    ], false),
    "TranslationMetadata": o([
        { json: "downloadUri", js: "downloadUri", typ: u(undefined, "") },
        { json: "fullDescription", js: "fullDescription", typ: u(undefined, r("MultiformatMessageString")) },
        { json: "fullName", js: "fullName", typ: u(undefined, "") },
        { json: "informationUri", js: "informationUri", typ: u(undefined, "") },
        { json: "name", js: "name", typ: "" },
        { json: "properties", js: "properties", typ: u(undefined, r("PropertyBag")) },
        { json: "shortDescription", js: "shortDescription", typ: u(undefined, r("MultiformatMessageString")) },
    ], false),
    "Graph": o([
        { json: "description", js: "description", typ: u(undefined, r("Message")) },
        { json: "edges", js: "edges", typ: u(undefined, a(r("Edge"))) },
        { json: "nodes", js: "nodes", typ: u(undefined, a(r("Node"))) },
        { json: "properties", js: "properties", typ: u(undefined, r("PropertyBag")) },
    ], false),
    "Edge": o([
        { json: "id", js: "id", typ: "" },
        { json: "label", js: "label", typ: u(undefined, r("Message")) },
        { json: "properties", js: "properties", typ: u(undefined, r("PropertyBag")) },
        { json: "sourceNodeId", js: "sourceNodeId", typ: "" },
        { json: "targetNodeId", js: "targetNodeId", typ: "" },
    ], false),
    "Node": o([
        { json: "children", js: "children", typ: u(undefined, a(r("Node"))) },
        { json: "id", js: "id", typ: "" },
        { json: "label", js: "label", typ: u(undefined, r("Message")) },
        { json: "location", js: "location", typ: u(undefined, r("Location")) },
        { json: "properties", js: "properties", typ: u(undefined, r("PropertyBag")) },
    ], false),
    "Result": o([
        { json: "analysisTarget", js: "analysisTarget", typ: u(undefined, r("ArtifactLocation")) },
        { json: "attachments", js: "attachments", typ: u(undefined, a(r("Attachment"))) },
        { json: "baselineState", js: "baselineState", typ: u(undefined, r("BaselineState")) },
        { json: "codeFlows", js: "codeFlows", typ: u(undefined, a(r("CodeFlow"))) },
        { json: "correlationGuid", js: "correlationGuid", typ: u(undefined, "") },
        { json: "fingerprints", js: "fingerprints", typ: u(undefined, m("")) },
        { json: "fixes", js: "fixes", typ: u(undefined, a(r("Fix"))) },
        { json: "graphs", js: "graphs", typ: u(undefined, a(r("Graph"))) },
        { json: "graphTraversals", js: "graphTraversals", typ: u(undefined, a(r("GraphTraversal"))) },
        { json: "guid", js: "guid", typ: u(undefined, "") },
        { json: "hostedViewerUri", js: "hostedViewerUri", typ: u(undefined, "") },
        { json: "kind", js: "kind", typ: u(undefined, r("ResultKind")) },
        { json: "level", js: "level", typ: u(undefined, r("Level")) },
        { json: "locations", js: "locations", typ: u(undefined, a(r("Location"))) },
        { json: "message", js: "message", typ: r("Message") },
        { json: "occurrenceCount", js: "occurrenceCount", typ: u(undefined, 0) },
        { json: "partialFingerprints", js: "partialFingerprints", typ: u(undefined, m("")) },
        { json: "properties", js: "properties", typ: u(undefined, r("PropertyBag")) },
        { json: "provenance", js: "provenance", typ: u(undefined, r("ResultProvenance")) },
        { json: "rank", js: "rank", typ: u(undefined, 3.14) },
        { json: "relatedLocations", js: "relatedLocations", typ: u(undefined, a(r("Location"))) },
        { json: "rule", js: "rule", typ: u(undefined, r("ReportingDescriptorReference")) },
        { json: "ruleId", js: "ruleId", typ: u(undefined, "") },
        { json: "ruleIndex", js: "ruleIndex", typ: u(undefined, 0) },
        { json: "stacks", js: "stacks", typ: u(undefined, a(r("Stack"))) },
        { json: "suppressions", js: "suppressions", typ: u(undefined, a(r("Suppression"))) },
        { json: "taxa", js: "taxa", typ: u(undefined, a(r("ReportingDescriptorReference"))) },
        { json: "webRequest", js: "webRequest", typ: u(undefined, r("WebRequest")) },
        { json: "webResponse", js: "webResponse", typ: u(undefined, r("WebResponse")) },
        { json: "workItemUris", js: "workItemUris", typ: u(undefined, a("")) },
    ], false),
    "Attachment": o([
        { json: "artifactLocation", js: "artifactLocation", typ: r("ArtifactLocation") },
        { json: "description", js: "description", typ: u(undefined, r("Message")) },
        { json: "properties", js: "properties", typ: u(undefined, r("PropertyBag")) },
        { json: "rectangles", js: "rectangles", typ: u(undefined, a(r("Rectangle"))) },
        { json: "regions", js: "regions", typ: u(undefined, a(r("Region"))) },
    ], false),
    "Rectangle": o([
        { json: "bottom", js: "bottom", typ: u(undefined, 3.14) },
        { json: "left", js: "left", typ: u(undefined, 3.14) },
        { json: "message", js: "message", typ: u(undefined, r("Message")) },
        { json: "properties", js: "properties", typ: u(undefined, r("PropertyBag")) },
        { json: "right", js: "right", typ: u(undefined, 3.14) },
        { json: "top", js: "top", typ: u(undefined, 3.14) },
    ], false),
    "CodeFlow": o([
        { json: "message", js: "message", typ: u(undefined, r("Message")) },
        { json: "properties", js: "properties", typ: u(undefined, r("PropertyBag")) },
        { json: "threadFlows", js: "threadFlows", typ: a(r("ThreadFlow")) },
    ], false),
    "ThreadFlow": o([
        { json: "id", js: "id", typ: u(undefined, "") },
        { json: "immutableState", js: "immutableState", typ: u(undefined, m(r("MultiformatMessageString"))) },
        { json: "initialState", js: "initialState", typ: u(undefined, m(r("MultiformatMessageString"))) },
        { json: "locations", js: "locations", typ: a(r("ThreadFlowLocation")) },
        { json: "message", js: "message", typ: u(undefined, r("Message")) },
        { json: "properties", js: "properties", typ: u(undefined, r("PropertyBag")) },
    ], false),
    "ThreadFlowLocation": o([
        { json: "executionOrder", js: "executionOrder", typ: u(undefined, 0) },
        { json: "executionTimeUtc", js: "executionTimeUtc", typ: u(undefined, Date) },
        { json: "importance", js: "importance", typ: u(undefined, r("Importance")) },
        { json: "index", js: "index", typ: u(undefined, 0) },
        { json: "kinds", js: "kinds", typ: u(undefined, a("")) },
        { json: "location", js: "location", typ: u(undefined, r("Location")) },
        { json: "module", js: "module", typ: u(undefined, "") },
        { json: "nestingLevel", js: "nestingLevel", typ: u(undefined, 0) },
        { json: "properties", js: "properties", typ: u(undefined, r("PropertyBag")) },
        { json: "stack", js: "stack", typ: u(undefined, r("Stack")) },
        { json: "state", js: "state", typ: u(undefined, m(r("MultiformatMessageString"))) },
        { json: "taxa", js: "taxa", typ: u(undefined, a(r("ReportingDescriptorReference"))) },
        { json: "webRequest", js: "webRequest", typ: u(undefined, r("WebRequest")) },
        { json: "webResponse", js: "webResponse", typ: u(undefined, r("WebResponse")) },
    ], false),
    "WebRequest": o([
        { json: "body", js: "body", typ: u(undefined, r("ArtifactContent")) },
        { json: "headers", js: "headers", typ: u(undefined, m("")) },
        { json: "index", js: "index", typ: u(undefined, 0) },
        { json: "method", js: "method", typ: u(undefined, "") },
        { json: "parameters", js: "parameters", typ: u(undefined, m("")) },
        { json: "properties", js: "properties", typ: u(undefined, r("PropertyBag")) },
        { json: "protocol", js: "protocol", typ: u(undefined, "") },
        { json: "target", js: "target", typ: u(undefined, "") },
        { json: "version", js: "version", typ: u(undefined, "") },
    ], false),
    "WebResponse": o([
        { json: "body", js: "body", typ: u(undefined, r("ArtifactContent")) },
        { json: "headers", js: "headers", typ: u(undefined, m("")) },
        { json: "index", js: "index", typ: u(undefined, 0) },
        { json: "noResponseReceived", js: "noResponseReceived", typ: u(undefined, true) },
        { json: "properties", js: "properties", typ: u(undefined, r("PropertyBag")) },
        { json: "protocol", js: "protocol", typ: u(undefined, "") },
        { json: "reasonPhrase", js: "reasonPhrase", typ: u(undefined, "") },
        { json: "statusCode", js: "statusCode", typ: u(undefined, 0) },
        { json: "version", js: "version", typ: u(undefined, "") },
    ], false),
    "Fix": o([
        { json: "artifactChanges", js: "artifactChanges", typ: a(r("ArtifactChange")) },
        { json: "description", js: "description", typ: u(undefined, r("Message")) },
        { json: "properties", js: "properties", typ: u(undefined, r("PropertyBag")) },
    ], false),
    "ArtifactChange": o([
        { json: "artifactLocation", js: "artifactLocation", typ: r("ArtifactLocation") },
        { json: "properties", js: "properties", typ: u(undefined, r("PropertyBag")) },
        { json: "replacements", js: "replacements", typ: a(r("Replacement")) },
    ], false),
    "Replacement": o([
        { json: "deletedRegion", js: "deletedRegion", typ: r("Region") },
        { json: "insertedContent", js: "insertedContent", typ: u(undefined, r("ArtifactContent")) },
        { json: "properties", js: "properties", typ: u(undefined, r("PropertyBag")) },
    ], false),
    "GraphTraversal": o([
        { json: "description", js: "description", typ: u(undefined, r("Message")) },
        { json: "edgeTraversals", js: "edgeTraversals", typ: u(undefined, a(r("EdgeTraversal"))) },
        { json: "immutableState", js: "immutableState", typ: u(undefined, m(r("MultiformatMessageString"))) },
        { json: "initialState", js: "initialState", typ: u(undefined, m(r("MultiformatMessageString"))) },
        { json: "properties", js: "properties", typ: u(undefined, r("PropertyBag")) },
        { json: "resultGraphIndex", js: "resultGraphIndex", typ: u(undefined, 0) },
        { json: "runGraphIndex", js: "runGraphIndex", typ: u(undefined, 0) },
    ], false),
    "EdgeTraversal": o([
        { json: "edgeId", js: "edgeId", typ: "" },
        { json: "finalState", js: "finalState", typ: u(undefined, m(r("MultiformatMessageString"))) },
        { json: "message", js: "message", typ: u(undefined, r("Message")) },
        { json: "properties", js: "properties", typ: u(undefined, r("PropertyBag")) },
        { json: "stepOverEdgeCount", js: "stepOverEdgeCount", typ: u(undefined, 0) },
    ], false),
    "ResultProvenance": o([
        { json: "conversionSources", js: "conversionSources", typ: u(undefined, a(r("PhysicalLocation"))) },
        { json: "firstDetectionRunGuid", js: "firstDetectionRunGuid", typ: u(undefined, "") },
        { json: "firstDetectionTimeUtc", js: "firstDetectionTimeUtc", typ: u(undefined, Date) },
        { json: "invocationIndex", js: "invocationIndex", typ: u(undefined, 0) },
        { json: "lastDetectionRunGuid", js: "lastDetectionRunGuid", typ: u(undefined, "") },
        { json: "lastDetectionTimeUtc", js: "lastDetectionTimeUtc", typ: u(undefined, Date) },
        { json: "properties", js: "properties", typ: u(undefined, r("PropertyBag")) },
    ], false),
    "Suppression": o([
        { json: "guid", js: "guid", typ: u(undefined, "") },
        { json: "justification", js: "justification", typ: u(undefined, "") },
        { json: "kind", js: "kind", typ: r("SuppressionKind") },
        { json: "location", js: "location", typ: u(undefined, r("Location")) },
        { json: "properties", js: "properties", typ: u(undefined, r("PropertyBag")) },
        { json: "status", js: "status", typ: u(undefined, r("Status")) },
    ], false),
    "Run": o([
        { json: "addresses", js: "addresses", typ: u(undefined, a(r("Address"))) },
        { json: "artifacts", js: "artifacts", typ: u(undefined, a(r("Artifact"))) },
        { json: "automationDetails", js: "automationDetails", typ: u(undefined, r("RunAutomationDetails")) },
        { json: "baselineGuid", js: "baselineGuid", typ: u(undefined, "") },
        { json: "columnKind", js: "columnKind", typ: u(undefined, r("ColumnKind")) },
        { json: "conversion", js: "conversion", typ: u(undefined, r("Conversion")) },
        { json: "defaultEncoding", js: "defaultEncoding", typ: u(undefined, "") },
        { json: "defaultSourceLanguage", js: "defaultSourceLanguage", typ: u(undefined, "") },
        { json: "externalPropertyFileReferences", js: "externalPropertyFileReferences", typ: u(undefined, r("ExternalPropertyFileReferences")) },
        { json: "graphs", js: "graphs", typ: u(undefined, a(r("Graph"))) },
        { json: "invocations", js: "invocations", typ: u(undefined, a(r("Invocation"))) },
        { json: "language", js: "language", typ: u(undefined, "") },
        { json: "logicalLocations", js: "logicalLocations", typ: u(undefined, a(r("LogicalLocation"))) },
        { json: "newlineSequences", js: "newlineSequences", typ: u(undefined, a("")) },
        { json: "originalUriBaseIds", js: "originalUriBaseIds", typ: u(undefined, m(r("ArtifactLocation"))) },
        { json: "policies", js: "policies", typ: u(undefined, a(r("ToolComponent"))) },
        { json: "properties", js: "properties", typ: u(undefined, r("PropertyBag")) },
        { json: "redactionTokens", js: "redactionTokens", typ: u(undefined, a("")) },
        { json: "results", js: "results", typ: u(undefined, a(r("Result"))) },
        { json: "runAggregates", js: "runAggregates", typ: u(undefined, a(r("RunAutomationDetails"))) },
        { json: "specialLocations", js: "specialLocations", typ: u(undefined, r("SpecialLocations")) },
        { json: "taxonomies", js: "taxonomies", typ: u(undefined, a(r("ToolComponent"))) },
        { json: "threadFlowLocations", js: "threadFlowLocations", typ: u(undefined, a(r("ThreadFlowLocation"))) },
        { json: "tool", js: "tool", typ: r("Tool") },
        { json: "translations", js: "translations", typ: u(undefined, a(r("ToolComponent"))) },
        { json: "versionControlProvenance", js: "versionControlProvenance", typ: u(undefined, a(r("VersionControlDetails"))) },
        { json: "webRequests", js: "webRequests", typ: u(undefined, a(r("WebRequest"))) },
        { json: "webResponses", js: "webResponses", typ: u(undefined, a(r("WebResponse"))) },
    ], false),
    "RunAutomationDetails": o([
        { json: "correlationGuid", js: "correlationGuid", typ: u(undefined, "") },
        { json: "description", js: "description", typ: u(undefined, r("Message")) },
        { json: "guid", js: "guid", typ: u(undefined, "") },
        { json: "id", js: "id", typ: u(undefined, "") },
        { json: "properties", js: "properties", typ: u(undefined, r("PropertyBag")) },
    ], false),
    "ExternalPropertyFileReferences": o([
        { json: "addresses", js: "addresses", typ: u(undefined, a(r("ExternalPropertyFileReference"))) },
        { json: "artifacts", js: "artifacts", typ: u(undefined, a(r("ExternalPropertyFileReference"))) },
        { json: "conversion", js: "conversion", typ: u(undefined, r("ExternalPropertyFileReference")) },
        { json: "driver", js: "driver", typ: u(undefined, r("ExternalPropertyFileReference")) },
        { json: "extensions", js: "extensions", typ: u(undefined, a(r("ExternalPropertyFileReference"))) },
        { json: "externalizedProperties", js: "externalizedProperties", typ: u(undefined, r("ExternalPropertyFileReference")) },
        { json: "graphs", js: "graphs", typ: u(undefined, a(r("ExternalPropertyFileReference"))) },
        { json: "invocations", js: "invocations", typ: u(undefined, a(r("ExternalPropertyFileReference"))) },
        { json: "logicalLocations", js: "logicalLocations", typ: u(undefined, a(r("ExternalPropertyFileReference"))) },
        { json: "policies", js: "policies", typ: u(undefined, a(r("ExternalPropertyFileReference"))) },
        { json: "properties", js: "properties", typ: u(undefined, r("PropertyBag")) },
        { json: "results", js: "results", typ: u(undefined, a(r("ExternalPropertyFileReference"))) },
        { json: "taxonomies", js: "taxonomies", typ: u(undefined, a(r("ExternalPropertyFileReference"))) },
        { json: "threadFlowLocations", js: "threadFlowLocations", typ: u(undefined, a(r("ExternalPropertyFileReference"))) },
        { json: "translations", js: "translations", typ: u(undefined, a(r("ExternalPropertyFileReference"))) },
        { json: "webRequests", js: "webRequests", typ: u(undefined, a(r("ExternalPropertyFileReference"))) },
        { json: "webResponses", js: "webResponses", typ: u(undefined, a(r("ExternalPropertyFileReference"))) },
    ], false),
    "ExternalPropertyFileReference": o([
        { json: "guid", js: "guid", typ: u(undefined, "") },
        { json: "itemCount", js: "itemCount", typ: u(undefined, 0) },
        { json: "location", js: "location", typ: u(undefined, r("ArtifactLocation")) },
        { json: "properties", js: "properties", typ: u(undefined, r("PropertyBag")) },
    ], false),
    "SpecialLocations": o([
        { json: "displayBase", js: "displayBase", typ: u(undefined, r("ArtifactLocation")) },
        { json: "properties", js: "properties", typ: u(undefined, r("PropertyBag")) },
    ], false),
    "VersionControlDetails": o([
        { json: "asOfTimeUtc", js: "asOfTimeUtc", typ: u(undefined, Date) },
        { json: "branch", js: "branch", typ: u(undefined, "") },
        { json: "mappedTo", js: "mappedTo", typ: u(undefined, r("ArtifactLocation")) },
        { json: "properties", js: "properties", typ: u(undefined, r("PropertyBag")) },
        { json: "repositoryUri", js: "repositoryUri", typ: "" },
        { json: "revisionId", js: "revisionId", typ: u(undefined, "") },
        { json: "revisionTag", js: "revisionTag", typ: u(undefined, "") },
    ], false),
    "Role": [
        "added",
        "analysisTarget",
        "attachment",
        "debugOutputFile",
        "deleted",
        "directory",
        "driver",
        "extension",
        "memoryContents",
        "modified",
        "policy",
        "referencedOnCommandLine",
        "renamed",
        "responseFile",
        "resultFile",
        "standardStream",
        "taxonomy",
        "toolSpecifiedConfiguration",
        "tracedFile",
        "translation",
        "uncontrolled",
        "unmodified",
        "userSpecifiedConfiguration",
    ],
    "Level": [
        "error",
        "none",
        "note",
        "warning",
    ],
    "Content": [
        "localizedData",
        "nonLocalizedData",
    ],
    "BaselineState": [
        "absent",
        "new",
        "unchanged",
        "updated",
    ],
    "Importance": [
        "essential",
        "important",
        "unimportant",
    ],
    "ResultKind": [
        "fail",
        "informational",
        "notApplicable",
        "open",
        "pass",
        "review",
    ],
    "SuppressionKind": [
        "external",
        "inSource",
    ],
    "Status": [
        "accepted",
        "rejected",
        "underReview",
    ],
    "Version": [
        "2.1.0",
    ],
    "ColumnKind": [
        "unicodeCodePoints",
        "utf16CodeUnits",
    ],
};
//# sourceMappingURL=secret-lint-types.js.map