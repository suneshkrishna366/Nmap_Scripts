description = [[
NetSentinel MQTT Protocol Scanner

Connects to an MQTT broker using the official Nmap MQTT
library and displays the broker connection information.
]]

author = "Sunesh Krishna"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe","discovery","version"}

local shortport = require "shortport"
local mqtt = require "mqtt"
local stdnse = require "stdnse"

portrule = shortport.port_or_service(1883, "mqtt", "tcp")

------------------------------------------------------------
-- Connect to Broker
------------------------------------------------------------

local function connect_to_broker(host, port)

    local helper = mqtt.Helper:new(host, port)

    return helper:connect({
        clean_session = true
    })

end

------------------------------------------------------------
-- Helper Function
------------------------------------------------------------

local function yes_no(value)

    if value then
        return "Yes"
    end

    return "No"

end

------------------------------------------------------------
-- Analyze Connection
------------------------------------------------------------

local function analyze_connection(connack, port)

    local result = {}

    result.reachable = true
    result.port = port.number
    result.accepted = connack.accepted
    result.session_present = connack.session_present

    result.observations = {}

    table.insert(result.observations,
        "CONNECT request sent successfully.")

    table.insert(result.observations,
        "Broker returned a CONNACK response.")

    if connack.accepted then

        table.insert(result.observations,
            "Broker accepted the client connection.")

    else

        table.insert(result.observations,
            "Broker rejected the client connection.")

        if connack.reason then
            table.insert(result.observations,
                "Reason : " .. connack.reason)
        end

    end

    if connack.session_present then

        table.insert(result.observations,
            "Session Present flag is enabled.")

    else

        table.insert(result.observations,
            "Session Present flag is disabled.")

    end

    return result

end

------------------------------------------------------------
-- Report Generator
------------------------------------------------------------

local function generate_report(result)

    local output = {}

    table.insert(output,"=========================================================")
    table.insert(output," NetSentinel MQTT Protocol Scanner")
    table.insert(output,"=========================================================")
    table.insert(output,"")

    table.insert(output,"Broker Information")
    table.insert(output,"------------------")
    table.insert(output,"Reachable           : " .. yes_no(result.reachable))
    table.insert(output,"Connection Accepted : " .. yes_no(result.accepted))
    table.insert(output,"Session Present     : " .. yes_no(result.session_present))
    table.insert(output,"")

    table.insert(output,"Protocol Details")
    table.insert(output,"----------------")
    table.insert(output,"Protocol : MQTT")
    table.insert(output,"Port     : " .. result.port)
    table.insert(output,"")

    table.insert(output,"Observations")
    table.insert(output,"------------")

    if #result.observations == 0 then
        table.insert(output,"None")
    else
        for _, item in ipairs(result.observations) do
            table.insert(output,item)
        end
    end

    table.insert(output,"")
    table.insert(output,"=========================================================")

    return stdnse.format_output(true, output)

end

------------------------------------------------------------
-- Action
------------------------------------------------------------

action = function(host, port)

    local status, connack = connect_to_broker(host, port)

    if not status then
        return "Connection Failed : " .. connack
    end

    local result = analyze_connection(connack, port)

    return generate_report(result)

end
