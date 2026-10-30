/*
 * Zabbix JavaScript Media Type payload for the local ChatOps bridge.
 * Keep params.URL as the bridge URL until Docker-to-host connectivity is
 * verified. This script does not call Slack directly and never carries a
 * Slack token.
 */
try {
    var params = JSON.parse(value),
        req = new HttpRequest(),
        get = function (name) {
            return params[name] === undefined || params[name] === null ? "" : String(params[name]);
        },
        payload = {
            source: "zabbix",
            event_id: get("EventID"),
            trigger_id: get("TriggerID"),
            host: get("Host"),
            severity: get("Severity"),
            status: get("Status"),
            value: get("Value"),
            subject: get("Subject"),
            message: get("Message"),
            item: get("Item"),
            timestamp: get("Timestamp"),
            DR_Escalate: get("DR_Escalate")
        };

    req.addHeader("Content-Type: application/json");
    req.addHeader("X-ChatOps-Source: zabbix");
    req.post(params.URL, JSON.stringify(payload));

    if (req.getStatus() < 200 || req.getStatus() >= 300) {
        throw "Response code: " + req.getStatus();
    }
    return "OK";
} catch (error) {
    Zabbix.log(4, "Zabbix ChatOps bridge failed: " + error);
    throw "Zabbix ChatOps bridge failed: " + error;
}
